# Parallel block decode (issue #80): design

## Problem

A compressed member is decoded on one core. `decoder50.fill` reads each
block's Huffman symbols and replays them into the window in one loop. On a
157 MB text member (`-m3 -md32m`, pinned to one core) the profile is:

| stage | share |
|---|---|
| symbol decode: `ReadSym` 38% cum, `PeekBits`, `ReadBits`, `slotToLength`, `decodeOffset` flat | ~58% |
| replay: `runtime.memmove` 30%, `CopyBytes` flat 7% | ~37% |
| block headers, tables, I/O | ~5% |

`unrar` decodes the same archive in 0.41 s on 2.3 cores against 0.57 s on
one. Replay is inherently serial within a member (every match reads the
window the previous matches wrote); symbol decode is not, because a block's
bits depend on nothing but the block's own bytes and the Huffman tables in
force when it started.

Two measurements that shape the design, taken on the same corpus and on
`testdata/rar5_solid_bench.rar`:

- rar writes **exactly 16384 symbols per block** (observed max 16384, mean
  16364; 1065 blocks for 157 MB of text, median packed payload 50 KB). The
  format allows a block of up to 16 MiB packed, so a bound is still needed,
  but the common case is small and uniform.
- the 30% in `memmove` is **call overhead on short matches**, not memory
  stalls: 16.5 M matches for 157 MB of output is 9.5 bytes per match, and
  9 ns per call. A short-match fast path is therefore worth trying first,
  and benefits the serial path too.

## Shape

unrar's shape (`unpack50mt.cpp`), adapted to this library's invariants.

```
caller goroutine (Entry.Read -> lz50Reader.Read -> decoder50.Read -> fill)
  |
  |  fillParallel
  |    1. top up the ring: read the next block header + payload from d.r,
  |       parse its code-length table if flagged (tables are sequential
  |       state), hand the job to the workers
  |    2. wait for the head job's items
  |    3. replay the head job's items into the window until the fill
  |       target is staged; when a job is exhausted, release its slot
  |
  +-- worker goroutines (N): job -> items, touching only the job's payload
      bytes and its (read-only) table set
```

Items are what unrar calls `UnpackDecodedItem`: everything a block's bits
determine on their own. Anything that depends on earlier output is deferred
to replay:

| symbol | worker emits | replay does |
|---|---|---|
| `< 256` literal | `itemLiteral{value: byte}` | `writeByte`, `decoded++` |
| `>= 262` match | `itemMatch{length, distance}` (length already carries the distance-dependent +1/+2/+3) | rotate `d.offset`, set `d.length`, `copyMatch`, `decoded += length` |
| `258..261` repeat distance slot i | `itemRepDist{aux: i, length}` (length read from the length table) | rotate `d.offset` by slot, set `d.length`, `copyMatch` |
| `257` repeat last | `itemRepLast` | `copyMatch` with current `d.length`, `d.offset[0]` |
| `256` filter | two items: `itemFilter{aux: ftype, length: param, value: offsetRaw}`, `itemFilterLen{value: lengthRaw}` | the body of today's `readFilter` from "bound both stream-supplied values" on: the `win.size` bound, `start = d.decoded + offset`, queue-order check, append |

An item is 8 bytes: `kind uint8, aux uint8, length uint16, value uint32`.
Distances fit `uint32` exactly (slot 63 with every extra bit set is
4294967295). Lengths fit `uint16` (slot 43 gives 3584+2, plus at most 3).

## Invariants this must keep

Each is a rule the repo learned from a real defect (CLAUDE.md), restated for
the parallel path:

1. **Bit-for-bit agreement with the serial path, including on damaged
   input.** Same bytes, same byte count before an error, same error
   identity, for every member. The compute functions are shared: the serial
   path and the worker call the same `decodeOffsetBits`,
   `decodeLengthBits`, `readFilterBits`; the serial path and replay call the
   same apply functions. A read-ahead error (corrupt block header, truncated
   source) is **deferred** until every block before it has been replayed,
   because that is when the serial path would have met it.
2. **`CopyBytes`'s history bound is applied at replay, unchanged.** Workers
   never see the window. `copyMatch`'s `ErrDictionaryTooLarge`
   classification runs at replay with the same inputs.
3. **`Entry.Read` stays allocation-free in steady state.** Job slots, item
   arrays, payload buffers and table sets are allocated when the pipeline
   starts and reused; `huffmanDecoder.symbol` slices are pre-grown by an
   `Init` on an all-zero table of the right size.
4. **Bounded memory for hostile input.** A block whose packed payload
   exceeds `maxParallelPayload` (4 MiB), or whose symbols overflow a slot's
   item array (`itemCap` = 32768; a filter takes two), is finished on the
   caller goroutine with the serial code from the exact bit position the
   worker stopped at, with that job's tables adopted. One mechanism covers
   both, and it keeps the serial path exercised.
5. **`Reader.Close` stops the workers and never blocks on them for longer
   than one block.** Workers exit on a quit channel; a replay waiting for a
   job selects on quit too, so Close cannot strand the traversal goroutine.
   `Reset` revives the pool. An abandoned member (`severActive`) leaves jobs
   in flight; `decoder50.init` drains them before reusing the slots.
6. **The solid-damage flag and the produced-size budget are untouched.**
   They live in `Entry` and `Reader`; the parallel path changes only how
   `fill` stages bytes into the window.
7. **Filters apply in order against `d.tot`**, so they are items and
   `readFilter`'s checks run at replay, where `d.decoded` is correct.

## Configuration

`Reader.SetWorkers(n int)`: `n <= 1` is the serial decoder (the default);
`n > 1` decodes blocks on `min(n, 8)` goroutines. Takes effect at the next
member. Default serial, because the gain is 1.4x wall at 1.5x CPU on
compressed members only and the consumer decides whether it has the cores;
the architecture study (rarengine-arch `DESIGN.md`) called for this behind a
flag.

Pipeline sizing at `n` workers: `R = 2n` job slots, `R + 1` table sets
(a slot references one set; `R + 1` guarantees a free one when a block
carries new tables). Per slot: payload buffer grown to the block's size (cap
`maxParallelPayload`), `itemCap` items (256 KiB). At 8 workers: about 4 MB
of items plus payloads, versus unrar's ~30 MB.

## Expected gain

Amdahl with the measured 58/37 split: `1 / (0.37 + 0.58/n)` is 1.46x at 2
workers, 1.94x at 4, 2.26x at 8, before pipeline overhead. unrar reaches
1.47x at its default of 8. The short-match fast path moves the split toward
decode and raises the ceiling further. Report whatever is measured, pinned
to one core for the serial baseline and unpinned for the parallel runs,
with `-mt1` and default `unrar t` on the same archive alongside.

## Not in scope

Member-level parallelism across non-solid members; a stage pipeline
(read/decode/hash/write); changing block structure or the Huffman decoder.
