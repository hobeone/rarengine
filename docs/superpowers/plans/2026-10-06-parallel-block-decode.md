# Parallel Block Decode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode a compressed member's RAR5 blocks into symbol items on worker goroutines while the caller goroutine replays them into the window, behind `Reader.SetWorkers(n)`, with byte-for-byte and error-for-error agreement with the serial decoder.

**Architecture:** Symbol decoding is split into pure "bits to values" functions shared by the serial path and the workers, and "apply to window" functions shared by the serial path and the replay. A ring of block jobs is filled by reading ahead on the caller goroutine (block header, payload, Huffman tables), decoded on workers into 8-byte items, and replayed in order. Anything a block cannot decide alone (distance history, filter start positions, the history bound) happens at replay. Oversize blocks and item overflow finish inline with the serial code from the exact bit position reached.

**Tech Stack:** Go 1.27, standard library only (`sync`, `runtime`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-06-parallel-block-decode-design.md` (read it first; the invariants section is the contract every task is checked against).

## Global Constraints

- Repo: `/home/hobe/software/rarengine/.claude/worktrees/parallel-decode`, branch `feat/80-parallel-block-decode`, based on main `9035a26`. Edit files with the Edit/Write tools, not shell redirection.
- Quality gate before every commit, run after staging: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`. All four must be clean. Tasks 5 and 6 add `go test -race -count=100 -run '<the new concurrency tests>' .` before their commit.
- Conventional Commits, lowercase imperative description, scope in parentheses when one subsystem (`feat(decoder)`, `refactor(decoder)`, `test(decoder)`, `perf(window)`, `docs`). Every commit message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (or the model actually writing it).
- Repo CLAUDE.md rules apply: AES key material never in errors or logs; well-formed RAR5 framing in tests comes only from `testbuild_test.go` helpers (`rar5Member`, `rar5Archive`, `volumesOf`); real archives from `testdata/`. Do not add fixtures made with `rar` except where a task says so (none here; the corpus measurements are not committed).
- No code comment may mention this plan, a task number or a step.
- Public API added: exactly one method, `func (r *Reader) SetWorkers(n int)`. No other exported names.
- A green test is evidence only after it has been seen red: every task that adds a test also states the mutation that must make it fail, and the step runs it.
- Keep `Entry.Read` allocation-free in steady state (Task 6 pins it).

## Review Focus

Inputs the spec implies but which no ordinary fixture exercises. Each line names the owning task where its test lives.

1. A block whose header is corrupt three blocks ahead of the replay position: the serial path delivers every byte of the earlier blocks first, then the error. The parallel path must not surface it early. Task 4, `TestParallelDefersReadAheadErrors`.
2. A block that overflows the item array (more than `itemCap` symbols): decoding must continue inline from the exact bit the worker stopped at, with that block's tables, and produce identical bytes. Task 3, `TestReplayResumesAfterItemOverflow` (with `itemCap` forced tiny).
3. `Reader.Close` from another goroutine while the traversal goroutine waits for a worker: the wait must end with `ErrReaderClosed`, no goroutine leaks, no deadlock. Task 5, `TestCloseWhileWaitingForWorkers`.
4. A member abandoned mid-decode (caller moves to `NextEntry` while jobs are in flight), then the next member decodes: slots and payload buffers must not be reused while a worker still writes them. Task 5, `TestAbandonedMemberDrainsInFlightJobs`.
5. Hostile table changes: a block with the `0x80` flag whose code-length table is invalid, arriving while earlier blocks are in flight. The error must surface only when replay reaches that block; the previous blocks' tables must be untouched. Task 4, `TestNewTablesFailingDoesNotDisturbInFlightBlocks`.

---

## File Structure

- `window.go` (modify): short-match fast path in `CopyBytes` (Task 1).
- `decoder50.go` (modify): `decoder50` gains `tables tableSet` in place of the four `huffmanDecoder` fields and a `pipe *blockPipeline`; `decodeOffset`/`decodeLength`/`readFilter` become thin wrappers over the shared compute and apply functions; `fill` routes to `fillParallel` when the pipeline is engaged; `readBlockHeader` is split so the dispatcher can reuse the header and payload reading (Task 2, 4).
- `decoder50_items.go` (create): `item`, `itemKind`, `tableSet`, the pure compute functions, the apply functions, `decodeBlockItems` and `replayItems` (Task 2, 3).
- `decoder50_parallel.go` (create): `blockJob`, `blockPipeline`, read-ahead, worker goroutines, `fillParallel`, start/stop/restart, drain (Task 4, 5).
- `reader.go` (modify): `SetWorkers`, pipeline stop in `Close`, restart in `Reset`, per-member engagement in `buildChain` (Task 5).
- Tests: `decoder50_golden_test.go` (Task 2), `decoder50_items_test.go` (Task 3), `decoder50_parallel_test.go` (Task 4, 5), `reader_workers_test.go` (Task 5, 6), `reader_benchmark_test.go` (Task 6).
- Docs: `CLAUDE.md`, `README.md` (Task 6).

---

### Task 1: Short-match fast path in `CopyBytes`

The profile shows 30% of decode time in `runtime.memmove` for matches averaging 9.5 bytes. A byte loop for short, non-wrapping, non-overlapping copies avoids the call. This task is measured and kept only if it helps; it has no functional change.

**Files:**
- Modify: `window.go:265-296` (`CopyBytes`)
- Test: `window_test.go` (existing tests cover semantics); benchmark in `reader_benchmark_test.go` (existing `BenchmarkDecompress_Solid`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `CopyBytes` unchanged in signature and semantics.

- [ ] **Step 1: Record the baseline**

Run, pinned, five times each (the machine is shared; see the number only as a ratio):

```bash
cd /home/hobe/software/rarengine/.claude/worktrees/parallel-decode
go test -c -o /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t1-base.test .
for i in 1 2 3 4 5; do taskset -c 6 /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t1-base.test -test.run XXX -test.bench 'BenchmarkDecompress_Solid$' -test.benchtime 1s; done 2>&1 | grep Benchmark > /home/hobe/.claude/jobs/99a0ece1/tmp/t1-base.txt
```

- [ ] **Step 2: Add the fast path**

In `CopyBytes`, after the bounds check and `srcIdx` computation, before `remaining := length`:

```go
	// Most matches are a few bytes: 9.5 on average over 16.5 M matches of
	// text. For those, one runtime.memmove call costs more than the copy. A
	// short match that neither wraps nor overlaps its source is copied here
	// with a plain loop; everything else takes the general path below, which
	// is also what preserves the pattern-repetition semantics when
	// length > distance.
	if length <= shortMatch && distance >= length &&
		srcIdx+length <= w.size && w.w+length <= w.size {
		dst := w.buf[w.w : w.w+length]
		src := w.buf[srcIdx : srcIdx+length]
		for i := range dst {
			dst[i] = src[i]
		}
		w.w += length
		if w.w == w.size {
			w.w = 0
			w.wrapped = true
		}
		if w.w == w.r {
			w.full = true
		}
		return nil
	}
```

Add to the `const` block at the top of `window.go`:

```go
	// shortMatch is the longest match copied with a byte loop rather than a
	// memmove call; see CopyBytes.
	shortMatch = 16
```

Note `w.w == w.size` (not `>=`): the guard above makes `w.w+length <= w.size`, so equality is the only wrap case, and `wrapped` must still be set then exactly as the general path sets it.

- [ ] **Step 3: Run the window and decoder tests**

Run: `go test -race -count=1 -run 'Window|CopyBytes|Decoder50|Dictionary' .`
Expected: PASS.

- [ ] **Step 4: Measure**

```bash
go test -c -o /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t1-new.test .
for i in 1 2 3 4 5; do taskset -c 6 /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t1-base.test -test.run XXX -test.bench 'BenchmarkDecompress_Solid$' -test.benchtime 1s >> /home/hobe/.claude/jobs/99a0ece1/tmp/t1-base.txt; taskset -c 6 /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t1-new.test -test.run XXX -test.bench 'BenchmarkDecompress_Solid$' -test.benchtime 1s >> /home/hobe/.claude/jobs/99a0ece1/tmp/t1-new.txt; done
benchstat /home/hobe/.claude/jobs/99a0ece1/tmp/t1-base.txt /home/hobe/.claude/jobs/99a0ece1/tmp/t1-new.txt
```

Decision rule: keep the change if `Decompress_Solid` sec/op improves by 5% or more with p < 0.05. Otherwise revert `window.go` with `git checkout window.go` and record the measured delta in the task report; the plan continues either way.

- [ ] **Step 5: Commit (only if kept)**

```bash
git add window.go
git commit -m "perf(window): copy short matches with a byte loop

Matches average under ten bytes on text, and a runtime.memmove call per
match was 30% of decode time. A match of at most 16 bytes that neither
wraps the ring nor overlaps its source is copied in place; the general
path is unchanged for everything else.

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Golden snapshot, then split symbol decode into compute and apply

Before touching the decoder, snapshot what it produces for every fixture. Then refactor so that "what the bits say" and "what that does to the window" are separate functions. The serial path uses both; later tasks use the first on workers and the second at replay. The snapshot proves the refactor changed nothing.

**Files:**
- Create: `decoder50_golden_test.go`, `testdata/decode_golden.tsv`
- Create: `decoder50_items.go`
- Modify: `decoder50.go:44-78` (struct), `:117-191` (`readBlockHeader`), `:234-440` (`readFilter`, `decodeLength`, `decodeOffset`, `decodeSymbol`)
- Modify: tests that reach the four decoders by field name (`grep -n 'mainDecoder\|offsetDecoder\|lowoffsetDecoder\|lengthDecoder' *_test.go`): rename to `d.tables.main` etc.

**Interfaces:**
- Produces, in `decoder50_items.go`:

```go
// tableSet is the four Huffman tables a block decodes with.
type tableSet struct {
	main, offset, lowoffset, length huffmanDecoder
}

// prewarm sizes every symbol slice so later load calls do not allocate.
func (ts *tableSet) prewarm()

// load initialises the four tables from a tableSize5-byte code-length table.
func (ts *tableSet) load(cl []byte) error

// copyFrom makes ts an independent copy of src: same tables, its own
// symbol slice storage, so a later load on either cannot disturb the other.
func (ts *tableSet) copyFrom(src *tableSet)

// Pure: bits in, values out. No window, no decoder state.
func decodeOffsetBits(br *bitReader, ts *tableSet, slot int) (length, distance int, err error)
func decodeLengthBits(br *bitReader, ts *tableSet) (length int, err error)
func readFilterBits(br *bitReader) (offset, length int64, ftype, param uint8, err error)

// Apply: decoder state and window in, same effects the serial path had.
func (d *decoder50) applyMatch(win *window, length, distance int) error
func (d *decoder50) applyRepDist(win *window, slot, length int) error
func (d *decoder50) applyRepLast(win *window) error
func (d *decoder50) queueFilter(win *window, offset, length int64, ftype, param uint8) error
```

- `decoder50` struct: the fields `mainDecoder, offsetDecoder, lowoffsetDecoder, lengthDecoder` are replaced by `tables tableSet`; `bitlenDecoder` stays.

- [ ] **Step 1: Write the golden generator and checker**

`decoder50_golden_test.go`:

```go
package rarengine

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// decodeOutcome is what a caller can observe of one member: the bytes it
// got (hashed), how many, and the error that ended it.
type decodeOutcome struct {
	file, name string
	index      int
	n          int64
	sum        string
	err        string
}

func (o decodeOutcome) line() string {
	return fmt.Sprintf("%s\t%d\t%s\t%d\t%s\t%s", o.file, o.index, o.name, o.n, o.sum, o.err)
}

// decodeAll reads every member of every fixture with the given Reader
// setup and returns the outcomes in traversal order. configure runs on a
// fresh Reader before the first NextEntry.
func decodeAll(t *testing.T, files []string, configure func(*Reader)) []decodeOutcome {
	t.Helper()
	var out []decodeOutcome
	for _, file := range files {
		r := NewReader(fileVolumesOf(t, file))
		if configure != nil {
			configure(r)
		}
		for i := 0; ; i++ {
			e, err := r.NextEntry()
			if errors.Is(err, io.EOF) {
				break
			}
			o := decodeOutcome{file: filepath.Base(file), index: i}
			if err != nil {
				o.err = err.Error()
				out = append(out, o)
				break
			}
			o.name = e.Header.Name
			h := sha256.New()
			n, rerr := io.Copy(h, e)
			o.n = n
			o.sum = hex.EncodeToString(h.Sum(nil))
			if rerr != nil {
				o.err = rerr.Error()
			}
			out = append(out, o)
		}
		_ = r.Close()
	}
	return out
}

// goldenFixtures is every single-volume fixture under testdata. Multi-volume
// sets are excluded because their volume order is a property of the test
// that uses them, not of the file names.
func goldenFixtures(t *testing.T) []string {
	t.Helper()
	all, err := filepath.Glob(filepath.Join("testdata", "*.rar"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range all {
		base := filepath.Base(f)
		if strings.Contains(base, ".part") {
			continue
		}
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

// The serial decoder's outcome on every fixture, as recorded before the
// decode path was split into compute and apply. Regenerate only when a
// change is MEANT to alter a verdict, with RARENGINE_WRITE_GOLDEN=1, and
// say so in the commit.
func TestSerialDecodeMatchesGolden(t *testing.T) {
	got := decodeAll(t, goldenFixtures(t), nil)
	path := filepath.Join("testdata", "decode_golden.tsv")
	if os.Getenv("RARENGINE_WRITE_GOLDEN") == "1" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriter(f)
		for _, o := range got {
			fmt.Fprintln(w, o.line())
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		t.Skip("golden rewritten")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	var want []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want = append(want, sc.Text())
	}
	if len(want) != len(got) {
		t.Fatalf("golden has %d outcomes, decoder produced %d", len(want), len(got))
	}
	for i := range got {
		if got[i].line() != want[i] {
			t.Errorf("outcome %d differs\n got: %s\nwant: %s", i, got[i].line(), want[i])
		}
	}
}
```

Check whether any fixture needs a password: `grep -rn 'SetPasswords' *_test.go | head`. If encrypted fixtures appear in the glob, their outcome will be the password error, which is fine: it is still a deterministic outcome.

- [ ] **Step 2: Generate the golden file on the unmodified decoder**

Run: `RARENGINE_WRITE_GOLDEN=1 go test -count=1 -run TestSerialDecodeMatchesGolden . && go test -count=1 -run TestSerialDecodeMatchesGolden . && wc -l testdata/decode_golden.tsv`
Expected: first run skips with "golden rewritten", second passes, the file has one line per member (expect somewhere above 100 lines).

- [ ] **Step 3: See it red**

Temporarily change `d.length, err = slotToLength(d.br, sl)` in `decodeLength` to `d.length, err = slotToLength(d.br, sl); d.length++`, run the test, expect failures on compressed fixtures with a different sum or an error. Revert the change (`git checkout decoder50.go`).

- [ ] **Step 4: Commit the golden**

```bash
git add decoder50_golden_test.go testdata/decode_golden.tsv
git commit -m "test(decoder): snapshot every fixture's decode outcome

The outcome is the bytes' hash, the byte count and the error that ended
the member, per member, for every single-volume fixture. The decode
path is about to be split for parallel decoding, and this is what
proves the split changed nothing.

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 5: Create `decoder50_items.go` with the table set and compute functions**

```go
package rarengine

// tableSet is the four Huffman tables a block is decoded with. Tables are
// sequential state: a block without the new-tables flag uses the tables of
// the block before it, so whoever reads block headers in order owns the
// current set and hands each block a reference to the set in force.
type tableSet struct {
	main, offset, lowoffset, length huffmanDecoder
}

// prewarm sizes each table's symbol slice for its alphabet, so that load
// never allocates afterwards. An all-zero code-length table is a valid
// (empty) tree for Init.
func (ts *tableSet) prewarm() {
	var zero [tableSize5]byte
	_ = ts.load(zero[:])
}

// load initialises the four tables from one tableSize5-byte code-length
// table, in the order the block header stores them.
func (ts *tableSet) load(cl []byte) error {
	if err := ts.main.Init(cl[:mainSize5]); err != nil {
		return err
	}
	cl = cl[mainSize5:]
	if err := ts.offset.Init(cl[:offsetSize5]); err != nil {
		return err
	}
	cl = cl[offsetSize5:]
	if err := ts.lowoffset.Init(cl[:lowoffsetSize5]); err != nil {
		return err
	}
	cl = cl[lowoffsetSize5:]
	return ts.length.Init(cl)
}

// copyFrom makes ts hold the same tables as src with its own symbol slice
// storage. huffmanDecoder.Init clears and refills the symbol slice in
// place, so two sets sharing one slice would corrupt each other on the
// next load; the arrays inside huffmanDecoder copy by value and need
// nothing more.
func (ts *tableSet) copyFrom(src *tableSet) {
	copyDecoder := func(dst, s *huffmanDecoder) {
		sym := dst.symbol
		*dst = *s
		if cap(sym) >= len(s.symbol) {
			sym = sym[:len(s.symbol)]
		} else {
			sym = make([]uint16, len(s.symbol))
		}
		copy(sym, s.symbol)
		dst.symbol = sym
	}
	copyDecoder(&ts.main, &src.main)
	copyDecoder(&ts.offset, &src.offset)
	copyDecoder(&ts.lowoffset, &src.lowoffset)
	copyDecoder(&ts.length, &src.length)
}

// decodeOffsetBits reads a match whose main symbol was 262+slot: the length
// from the slot and its extra bits, the distance from the offset tables,
// then the distance-dependent length adjustment. It touches no decoder
// state and no window, so it can run anywhere the block's bits and tables
// are.
func decodeOffsetBits(br *bitReader, ts *tableSet, slot int) (length, distance int, err error) {
	length, err = slotToLength(br, slot)
	if err != nil {
		return 0, 0, err
	}
	distance = 1
	oslot, err := ts.offset.ReadSym(br)
	if err != nil {
		return 0, 0, err
	}
	if oslot < 4 {
		distance += oslot
	} else {
		bitCount := uint8(oslot/2 - 1)
		distance += (2 | (oslot & 1)) << bitCount
		if bitCount >= 4 {
			bitCount -= 4
			if bitCount > 0 {
				n, err := br.ReadBits(bitCount)
				if err != nil {
					return 0, 0, err
				}
				distance += n << 4
			}
			n, err := ts.lowoffset.ReadSym(br)
			if err != nil {
				return 0, 0, err
			}
			distance += n
		} else {
			n, err := br.ReadBits(bitCount)
			if err != nil {
				return 0, 0, err
			}
			distance += n
		}
	}
	if distance > 0x100 {
		length++
		if distance > 0x2000 {
			length++
			if distance > 0x40000 {
				length++
			}
		}
	}
	return length, distance, nil
}

// decodeLengthBits reads the length that follows a repeat-distance symbol
// (258..261).
func decodeLengthBits(br *bitReader, ts *tableSet) (int, error) {
	sl, err := ts.length.ReadSym(br)
	if err != nil {
		return 0, err
	}
	return slotToLength(br, sl)
}

// readFilterBits reads a filter record's fields. The bounds and the start
// position depend on the window and on how much has been decoded, so they
// are left to queueFilter.
func readFilterBits(br *bitReader) (offset, length int64, ftype, param uint8, err error) {
	offset, err = readFilter5Data(br)
	if err != nil {
		return
	}
	length, err = readFilter5Data(br)
	if err != nil {
		return
	}
	t, err := br.ReadBits(3)
	if err != nil {
		return
	}
	ftype = uint8(t)
	if ftype == 0 {
		n, rerr := br.ReadBits(5)
		if rerr != nil {
			err = rerr
			return
		}
		param = uint8(n + 1)
	}
	return
}

// applyMatch records a new (length, distance) pair as the most recent and
// copies it. The distance history rotates by one, as unrar's does.
func (d *decoder50) applyMatch(win *window, length, distance int) error {
	d.offset[3] = d.offset[2]
	d.offset[2] = d.offset[1]
	d.offset[1] = d.offset[0]
	d.offset[0] = distance
	d.length = length
	if err := d.copyMatch(win); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// applyRepDist reuses the distance slot positions back in the history,
// moving it to the front, with a freshly read length.
func (d *decoder50) applyRepDist(win *window, slot, length int) error {
	distance := d.offset[slot]
	copy(d.offset[1:slot+1], d.offset[:slot])
	d.offset[0] = distance
	d.length = length
	if err := d.copyMatch(win); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// applyRepLast repeats the last match exactly.
func (d *decoder50) applyRepLast(win *window) error {
	if err := d.copyMatch(win); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// queueFilter validates a filter record against the window and the decode
// position and queues it. This is the half of the old readFilter that needs
// the window; readFilterBits is the other half.
func (d *decoder50) queueFilter(win *window, offset, length int64, ftype, param uint8) error {
	if len(d.fl) >= maxQueuedFilters {
		return ErrTooManyFilters
	}
	// Bound both stream-supplied values, which reach 0xFFFFFFFF. A filter is
	// announced while the decoder is near its position, so an offset beyond
	// one window is malformed rather than merely distant. Both are
	// non-negative by construction, so an upper bound is the whole check.
	if length > maxFilterBlockSize || offset > int64(win.size) {
		return ErrInvalidFilter
	}
	// The filter starts offset bytes past the decode head, which is where
	// the stream is as this record is parsed.
	start := d.decoded + offset
	// Filters are applied in queue order, so a block starting before the
	// last one queued is malformed.
	if n := len(d.fl); n > 0 && start < d.fl[n-1].start {
		return ErrInvalidFilter
	}
	if ftype > 3 {
		return ErrUnknownFilter
	}
	// A zero-length block transforms nothing. Dropping it here rather than
	// at dequeue keeps Read from returning (0, nil) against a non-empty
	// buffer, which would violate io.Reader.
	if length == 0 {
		return nil
	}
	d.fl = append(d.fl, filterBlock{
		start:  start,
		length: int(length), // bounded above at 4 MB, so exact on every platform
		ftype:  ftype,
		param:  param,
	})
	return nil
}
```

Order of checks in `queueFilter` versus the old `readFilter`: the old code checked `maxQueuedFilters` before reading any bits, bounds after reading all fields, and `ErrUnknownFilter` in the type switch after the bounds. With `readFilterBits` reading bits first, the queue-full check moves after the read. That changes which error wins only when the queue is full AND the bits are truncated; the truncated-bits error (`io.EOF`, mapped to `ErrDecoderOutOfData`) then wins where `ErrTooManyFilters` won before. Keep the old order instead: make `decodeSymbol`'s filter arm check `len(d.fl) >= maxQueuedFilters` BEFORE calling `readFilterBits`, and have `queueFilter` check it again (harmless, and the worker path has no d.fl to check, so replay relies on the second check). The golden test will tell you if the order still differs anywhere; `TestReadFilterRejectsHugeValues`, `TestReadFilterRejectsOversize` and `TestDecoder50_ReadFilter` pin the individual verdicts.

- [ ] **Step 6: Rewire `decoder50.go` onto the shared functions**

In the struct, replace the four decoder fields:

```go
	tables        tableSet
	bitlenDecoder huffmanDecoder // scratch for ReadCodeLengthTable
```

In `newDecoder50`, prewarm:

```go
func newDecoder50() *decoder50 {
	d := &decoder50{
		fl: make([]filterBlock, 0, maxQueuedFilters),
	}
	d.tables.prewarm()
	return d
}
```

In `readBlockHeader`, replace the four `Init` calls with:

```go
	if flags&0x80 > 0 {
		if err = readCodeLengthTable(d.br, d.codeLength[:], &d.bitlenDecoder); err != nil {
			return err
		}
		if err = d.tables.load(d.codeLength[:]); err != nil {
			return err
		}
	}
```

Replace `readFilter`, `decodeLength`, `decodeOffset` bodies:

```go
func (d *decoder50) readFilter(win *window) error {
	if len(d.fl) >= maxQueuedFilters {
		return ErrTooManyFilters
	}
	offset, length, ftype, param, err := readFilterBits(d.br)
	if err != nil {
		return err
	}
	return d.queueFilter(win, offset, length, ftype, param)
}

func (d *decoder50) decodeLength(win *window, slot int) error {
	length, err := decodeLengthBits(d.br, &d.tables)
	if err != nil {
		return err
	}
	return d.applyRepDist(win, slot, length)
}

func (d *decoder50) decodeOffset(win *window, slot int) error {
	length, distance, err := decodeOffsetBits(d.br, &d.tables, slot)
	if err != nil {
		return err
	}
	return d.applyMatch(win, length, distance)
}
```

Note one behavioural detail the old `decodeLength` had: it rotated `d.offset` BEFORE reading the length bits, so a truncated length left the history rotated. `applyRepDist` rotates after. On truncation the member ends with an error either way and `init(reset)` zeroes the history for the next non-solid member, while a solid successor is refused as broken, so no later observable depends on the rotated state. The golden test confirms; if it disagrees on any fixture, restore the old order inside `decodeLength` (rotate first, then read) and keep `applyRepDist` as the replay version, noting the difference in a comment.

`decodeSymbol`'s `case sym == 257` becomes `return d.applyRepLast(win)`. In `fill`, `d.mainDecoder.ReadSym(d.br)` becomes `d.tables.main.ReadSym(d.br)`.

Fix test references: `grep -n 'mainDecoder\|offsetDecoder\|lowoffsetDecoder\|lengthDecoder' *_test.go` and rename each to the `d.tables.<name>` form.

- [ ] **Step 7: Run the golden and the whole suite**

Run: `goimports -w . && go vet ./... && go test -race -count=1 ./...`
Expected: PASS, including `TestSerialDecodeMatchesGolden`. If the golden fails, the refactor changed behaviour: find the fixture, diff the serial logic against the old code line by line, fix the refactor (never the golden).

- [ ] **Step 8: Commit**

```bash
git add decoder50.go decoder50_items.go $(git diff --name-only -- '*_test.go')
git commit -m "refactor(decoder): split symbol decode into compute and apply

What a block's bits say (lengths, distances, filter fields) is now read
by functions that take only a bit reader and a table set; what that
does to the window and the distance history is applied by functions on
the decoder. The serial path calls both in sequence and the golden
snapshot shows every fixture decodes as before. Workers will call the
first half, replay the second.

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Items, block decode, replay (no goroutines yet)

Everything in this task runs on one goroutine. It proves that "decode a block to items, then replay the items" produces the same window writes as the serial loop, including when the item array overflows and decoding has to resume inline.

**Files:**
- Modify: `decoder50_items.go` (add `item`, `itemKind`, `blockJob` fields used by decode and replay, `decodeBlockItems`, `replayItems`, `finishBlockInline`)
- Test: `decoder50_items_test.go`

**Interfaces:**
- Produces:

```go
type itemKind uint8

const (
	itemLiteral   itemKind = iota // value: the byte
	itemMatch                     // length, value: distance
	itemRepDist                   // aux: slot 0..3, length
	itemRepLast                   //
	itemFilter                    // aux: ftype, length: param, value: offset (raw, <= 0xFFFFFFFF)
	itemFilterLen                 // value: length (raw); always follows itemFilter
)

// item is one decoded symbol with everything the block's bits determined.
type item struct {
	kind   itemKind
	aux    uint8
	length uint16
	value  uint32
}

const (
	// itemCap is a job's item array size: twice rar's 16384 symbols per
	// block, so a filter's two items and any encoder that packs more never
	// overflow in practice; the overflow path exists for the format's
	// 16 MiB blocks and for hostile input.
	itemCap = 32768
)

// blockJob is one block in flight: its bytes, the tables it decodes with,
// and what the worker produced.
type blockJob struct {
	payload   []byte
	bits      int
	lastBlock bool
	tables    *tableSet

	items   []item // len itemCap, filled to n
	n       int
	partial bool      // items filled before the block ended; resume holds the position
	resume  bitReader // the reader state at the first undecoded symbol
	err     error     // the error that ended decoding, nil at a clean block end

	done chan struct{} // buffered 1; the worker sends when the job is complete
}

// decodeBlockItems decodes j.payload into j.items. It is the worker's whole
// job and touches nothing but j and j.tables (read-only).
func decodeBlockItems(j *blockJob)

// replayItems applies j.items[*idx:] to the window until the window stages
// target bytes or the items run out, advancing *idx. It returns true when
// the job's items are exhausted.
func (d *decoder50) replayItems(win *window, j *blockJob, idx *int, target int) (exhausted bool, err error)

// finishBlockInline decodes the rest of a partial block with the serial
// code, from j.resume with j.tables adopted into d.tables, until the block
// ends or the window stages target bytes. It returns true when the block
// has ended.
func (d *decoder50) finishBlockInline(win *window, j *blockJob, target int) (blockDone bool, err error)
```

- [ ] **Step 1: Write the agreement test**

`decoder50_items_test.go`:

```go
package rarengine

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// serialBlocks decodes the first compressed member of file with the serial
// decoder, one block at a time, and returns for each block the bytes it
// wrote into the window. The window is drained after every symbol so that
// "bytes written" is observable without a second window.
func serialBlocks(t *testing.T, file string) (blocks [][]byte, jobs []*blockJob) {
	t.Helper()
	r := NewReader(fileVolumesOf(t, file))
	t.Cleanup(func() { _ = r.Close() })
	e := firstCompressedMember(t, r)
	d, win := r.dec50, r.win
	_ = e
	drain := make([]byte, win.size)
	for {
		if err := d.readBlockHeader(); err != nil {
			t.Fatalf("readBlockHeader: %v", err)
		}
		// Snapshot the block for the item decoder: payload copy, bit count,
		// the tables in force.
		j := &blockJob{
			payload:   bytes.Clone(d.payloadBuf),
			bits:      d.bitReader.limit,
			lastBlock: d.lastBlock,
			tables:    &tableSet{},
			items:     make([]item, itemCap),
			done:      make(chan struct{}, 1),
		}
		j.tables.copyFrom(&d.tables)
		// The worker starts after the tables; so must the snapshot.
		j.resume = d.bitReader
		jobs = append(jobs, j)

		var out []byte
		for {
			sym, err := d.tables.main.ReadSym(d.br)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("ReadSym: %v", err)
			}
			if err := d.decodeSymbol(win, sym); err != nil {
				t.Fatalf("decodeSymbol: %v", err)
			}
			n, _ := win.Read(drain)
			out = append(out, drain[:n]...)
		}
		blocks = append(blocks, out)
		if d.lastBlock {
			return blocks, jobs
		}
		d.br = nil
	}
}

func firstCompressedMember(t *testing.T, r *Reader) *Entry {
	t.Helper()
	for {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("no compressed member: %v", err)
		}
		if e.Header.Method != 0 {
			return e
		}
		if _, err := io.Copy(io.Discard, e); err != nil {
			t.Fatal(err)
		}
	}
}

// Decoding a block to items and replaying them writes exactly the bytes the
// serial loop wrote, block for block, on a real multi-block member.
// Mutation check: make applyMatch rotate the history in the wrong order and
// the second block's bytes differ.
func TestReplayMatchesSerialBlockForBlock(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	blocks, jobs := serialBlocks(t, file)
	if len(blocks) < 10 {
		t.Fatalf("fixture has %d blocks, need a multi-block member", len(blocks))
	}

	// A fresh decoder and window replay from the snapshots.
	d := newDecoder50()
	d.init(nil, true)
	win := newWindow(minWindowSize)
	if err := win.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	drain := make([]byte, win.size)
	for i, j := range jobs {
		// j.resume was snapshotted right after readBlockHeader, so it is
		// positioned after the block's tables: exactly where the dispatcher
		// will leave it for a worker.
		decodeBlockItems(j)
		if j.err != nil {
			t.Fatalf("block %d: worker error %v", i, j.err)
		}
		if j.partial {
			t.Fatalf("block %d: overflowed %d items", i, itemCap)
		}
		var out []byte
		idx := 0
		for {
			exhausted, err := d.replayItems(win, j, &idx, 1)
			if err != nil {
				t.Fatalf("block %d: replay %v", i, err)
			}
			n, _ := win.Read(drain)
			out = append(out, drain[:n]...)
			if exhausted {
				break
			}
		}
		if !bytes.Equal(out, blocks[i]) {
			t.Fatalf("block %d: replay wrote %d bytes, serial wrote %d (first difference at %d)",
				i, len(out), len(blocks[i]), firstDiff(out, blocks[i]))
		}
	}
}

func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
```

Contract settled here and relied on by Task 4: **`decodeBlockItems` starts at `j.resume` when `j.resume.buf != nil`, otherwise at the payload's first bit.** The dispatcher always sets `resume` to the position after the tables, because the tables are sequential state the dispatcher owns; a worker that re-read them from the payload would need the bit-length scratch and would race the dispatcher's table set.

- [ ] **Step 2: Run it to see it fail to compile**

Run: `go test -count=1 -run TestReplayMatchesSerialBlockForBlock .`
Expected: FAIL, undefined `blockJob`, `decodeBlockItems`, `replayItems`.

- [ ] **Step 3: Implement items, decode and replay**

Append to `decoder50_items.go`:

```go
type itemKind uint8

const (
	itemLiteral itemKind = iota
	itemMatch
	itemRepDist
	itemRepLast
	itemFilter
	itemFilterLen
)

// item is one decoded symbol with everything the block's bits determined on
// their own. What depends on earlier output -- the distance history, the
// decode position a filter is relative to, the window's history bound -- is
// resolved when the item is replayed. 8 bytes: a distance fits uint32
// exactly (slot 63 with every extra bit set is 4294967295) and a length
// fits uint16 (slot 43 is 3586 before the at most +3 adjustment).
type item struct {
	kind   itemKind
	aux    uint8
	length uint16
	value  uint32
}

const itemCap = 32768

type blockJob struct {
	payload   []byte
	bits      int
	lastBlock bool
	tables    *tableSet

	items   []item
	n       int
	partial bool
	resume  bitReader
	err     error

	done chan struct{}
}

// decodeBlockItems turns j's bits into items. It starts at j.resume when
// that reader has a buffer (the dispatcher leaves it positioned after the
// block's tables) and at the payload's first bit otherwise. A clean block
// end is j.err == nil; an error that ended the block is recorded as the
// serial path would have reported it from fill. If the items fill up first,
// j.partial is set and j.resume is left at the first undecoded symbol.
func decodeBlockItems(j *blockJob) {
	br := &j.resume
	if br.buf == nil {
		br.Reset(j.payload, j.bits)
	}
	ts := j.tables
	j.n = 0
	j.partial = false
	j.err = nil
	for {
		if j.n >= len(j.items)-1 { // a filter needs two slots
			j.partial = true
			return
		}
		sym, err := ts.main.ReadSym(br)
		if err != nil {
			if err == io.EOF {
				return
			}
			j.err = err
			return
		}
		it := &j.items[j.n]
		switch {
		case sym < 256:
			*it = item{kind: itemLiteral, value: uint32(sym)}
			j.n++
		case sym >= 262:
			length, distance, err := decodeOffsetBits(br, ts, sym-262)
			if err != nil {
				j.err = mapInnerErr(err)
				return
			}
			*it = item{kind: itemMatch, length: uint16(length), value: uint32(distance)}
			j.n++
		case sym >= 258:
			length, err := decodeLengthBits(br, ts)
			if err != nil {
				j.err = mapInnerErr(err)
				return
			}
			*it = item{kind: itemRepDist, aux: uint8(sym - 258), length: uint16(length)}
			j.n++
		case sym == 257:
			*it = item{kind: itemRepLast}
			j.n++
		default: // 256
			offset, length, ftype, param, err := readFilterBits(br)
			if err != nil {
				j.err = mapInnerErr(err)
				return
			}
			*it = item{kind: itemFilter, aux: ftype, length: uint16(param), value: uint32(offset)}
			j.items[j.n+1] = item{kind: itemFilterLen, value: uint32(length)}
			j.n += 2
		}
	}
}

// mapInnerErr is fill's mapping for an error from inside a symbol: running
// out of bits mid-symbol is ErrDecoderOutOfData, not a clean end.
func mapInnerErr(err error) error {
	if err == io.EOF {
		return ErrDecoderOutOfData
	}
	return err
}

// replayItems applies j.items[*idx:] to the window until target bytes are
// staged or the items run out. It is the serial loop's apply half, driven
// from the item array instead of from the bit reader.
func (d *decoder50) replayItems(win *window, j *blockJob, idx *int, target int) (bool, error) {
	for *idx < j.n {
		if win.Available() >= target {
			return false, nil
		}
		it := j.items[*idx]
		*idx++
		var err error
		switch it.kind {
		case itemLiteral:
			win.writeByte(byte(it.value))
			d.decoded++
		case itemMatch:
			err = d.applyMatch(win, int(it.length), int(it.value))
		case itemRepDist:
			err = d.applyRepDist(win, int(it.aux), int(it.length))
		case itemRepLast:
			err = d.applyRepLast(win)
		case itemFilter:
			if len(d.fl) >= maxQueuedFilters {
				return false, ErrTooManyFilters
			}
			if *idx >= j.n || j.items[*idx].kind != itemFilterLen {
				return false, ErrCorruptDecodeHeader
			}
			ln := j.items[*idx]
			*idx++
			err = d.queueFilter(win, int64(it.value), int64(ln.value), it.aux, uint8(it.length))
		default:
			return false, ErrCorruptDecodeHeader
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// finishBlockInline continues a block the worker left partial. The serial
// code takes over from the saved reader position with the job's tables,
// and runs until the block ends or the window stages target bytes. While
// it runs, d.br is the live reader, so a caller that sees blockDone false
// must call again before touching any other block.
func (d *decoder50) finishBlockInline(win *window, j *blockJob, target int) (bool, error) {
	if d.br == nil {
		d.tables.copyFrom(j.tables)
		d.bitReader = j.resume
		d.br = &d.bitReader
		d.lastBlock = j.lastBlock
	}
	for win.Available() < target {
		sym, err := d.tables.main.ReadSym(d.br)
		if err != nil {
			if err == io.EOF {
				d.br = nil
				return true, nil
			}
			return true, err
		}
		if err := d.decodeSymbol(win, sym); err != nil {
			return true, mapInnerErr(err)
		}
	}
	return false, nil
}
```

Note the filter arm in `decodeBlockItems` reserves two slots: the `len(j.items)-1` check at the loop top guarantees room. Check `j.items` has `len` `itemCap` (not just cap) wherever jobs are built.

`fill`'s own mapping `if err == io.EOF { return ErrDecoderOutOfData }` after `decodeSymbol` is what `mapInnerErr` reproduces; leave `fill` as it is.

- [ ] **Step 4: Run the agreement test**

Run: `go test -count=1 -run TestReplayMatchesSerialBlockForBlock -v .`
Expected: PASS.

- [ ] **Step 5: Mutation check**

In `applyMatch`, swap the two lines `d.offset[2] = d.offset[1]` and `d.offset[1] = d.offset[0]`. Run the test; expect a failure naming a block and a byte offset. Revert.

- [ ] **Step 6: Overflow and resume test**

Append to `decoder50_items_test.go`:

```go
// When the items fill up before the block ends, decoding resumes inline
// from the exact bit the worker stopped at, with the block's tables, and
// the bytes are still the serial bytes. The item array is made tiny so a
// real block overflows many times over.
// Mutation check: make finishBlockInline start from a fresh Reset of the
// payload instead of j.resume and every block's bytes differ.
func TestReplayResumesAfterItemOverflow(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	blocks, jobs := serialBlocks(t, file)

	d := newDecoder50()
	d.init(nil, true)
	win := newWindow(minWindowSize)
	if err := win.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	drain := make([]byte, win.size)
	overflowed := 0
	for i, j := range jobs {
		j.items = make([]item, 64)
		var out []byte
		for {
			decodeBlockItems(j)
			if j.err != nil {
				t.Fatalf("block %d: %v", i, j.err)
			}
			idx := 0
			for {
				exhausted, err := d.replayItems(win, j, &idx, 1)
				if err != nil {
					t.Fatalf("block %d: replay %v", i, err)
				}
				n, _ := win.Read(drain)
				out = append(out, drain[:n]...)
				if exhausted {
					break
				}
			}
			if !j.partial {
				break
			}
			overflowed++
			// Finish the block inline, draining as the serial loop did.
			for {
				done, err := d.finishBlockInline(win, j, 1)
				if err != nil {
					t.Fatalf("block %d: inline %v", i, err)
				}
				n, _ := win.Read(drain)
				out = append(out, drain[:n]...)
				if done {
					break
				}
			}
			break
		}
		if !bytes.Equal(out, blocks[i]) {
			t.Fatalf("block %d: %d bytes, serial %d, first difference %d",
				i, len(out), len(blocks[i]), firstDiff(out, blocks[i]))
		}
	}
	if overflowed == 0 {
		t.Fatal("no block overflowed 64 items; the resume path was not exercised")
	}
}
```

Run: `go test -count=1 -run TestReplayResumesAfterItemOverflow -v .`
Expected: PASS, and the mutation (replace `d.bitReader = j.resume` with `d.bitReader.Reset(j.payload, j.bits)`) fails it. Revert the mutation.

- [ ] **Step 7: Gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add decoder50_items.go decoder50_items_test.go
git commit -m "feat(decoder): decode a block to items and replay them

A block's symbols become 8-byte items holding what the bits determined;
the distance history, filter positions and the history bound are
resolved when the items are replayed into the window, by the same apply
functions the serial path uses. A block that overflows its item array is
finished inline from the exact bit reached. No goroutines yet: this pins
that items plus replay write the serial bytes, block for block.

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: The pipeline, synchronous

Build the ring, the table-set lifecycle, read-ahead, deferred errors and `fillParallel`, with blocks decoded inline by the dispatcher (no worker goroutines). This isolates every ordering question from every concurrency question. Task 5 adds goroutines without changing the ring.

**Files:**
- Create: `decoder50_parallel.go`
- Modify: `decoder50.go` (`fill` routing; split `readBlockHeader` into `readBlockHead` + payload read so the dispatcher can reuse them; `init` drains the pipeline)
- Test: `decoder50_parallel_test.go`

**Interfaces:**
- Produces:

```go
const (
	maxWorkers         = 8
	maxParallelPayload = 4 << 20 // a block bigger than this is decoded inline
)

// blockHead is a parsed block header, before its payload is read.
type blockHead struct {
	blockBytes int
	blockBits  int
	newTables  bool
	lastBlock  bool
}

// readBlockHead reads and validates the 2..5 header bytes from r.
func readBlockHead(r io.Reader) (blockHead, error)

type blockPipeline struct {
	workers int

	slots       []*blockJob // ring storage, len R = 2*workers
	head, count int         // ring: slots[head] is the oldest in flight
	idx         int         // replay position within slots[head]
	inline      bool        // slots[head] is being finished inline (partial or oversize)

	tables []*tableSet // R+1 sets
	inUse  []int       // jobs referencing tables[i]
	cur    int         // the set the next block uses unless it carries new tables

	pendingErr error // a read-ahead error, surfaced when the ring drains
	sawLast    bool  // the last block has been read ahead
	engaged    bool  // this member is being decoded through the pipeline

	codeLength [tableSize5]byte
	bitlen     huffmanDecoder

	// Task 5 adds: jobs chan *blockJob, quit chan struct{}, wg sync.WaitGroup, mu sync.Mutex, running bool
}

func newBlockPipeline(workers int) *blockPipeline

// engage prepares the pipeline for a member: ring empty, flags cleared,
// current tables seeded from the serial decoder's tables.
func (p *blockPipeline) engage(d *decoder50)

// disengage copies the current tables back to the serial decoder so a
// later serial member sees the tables a parallel member left.
func (p *blockPipeline) disengage(d *decoder50)

// readAhead fills free slots with blocks from d.r until the ring is full,
// the last block is read, or a read error is recorded in pendingErr.
func (p *blockPipeline) readAhead(d *decoder50)

// submit hands a job to the workers. In this task it decodes inline.
func (p *blockPipeline) submit(j *blockJob)

// wait blocks until slots[head] is decoded. In this task it returns at once.
func (p *blockPipeline) wait(j *blockJob) error

// pop releases slots[head].
func (p *blockPipeline) pop()

// fillParallel is fill for an engaged pipeline.
func (d *decoder50) fillParallel(win *window) error
```

- [ ] **Step 1: Split `readBlockHeader`**

In `decoder50.go`, replace lines 117-165 of `readBlockHeader` (everything up to and including `d.lastBlock = flags&0x40 > 0`) with a call to the new pieces:

```go
// readBlockHead reads a block's header bytes: flags, checksum, the payload
// byte count. It reads nothing of the payload.
func readBlockHead(r io.Reader) (blockHead, error) {
	var temp [2]byte
	if _, err := io.ReadFull(r, temp[:]); err != nil {
		return blockHead{}, err
	}
	flags := temp[0]
	hsum := temp[1]

	bytecount := (flags>>3)&3 + 1
	if bytecount == 4 {
		return blockHead{}, ErrCorruptDecodeHeader
	}

	h := blockHead{blockBits: int(flags)&0x07 + 1}
	sum := 0x5a ^ flags
	var blockBytesBuf [3]byte
	if _, err := io.ReadFull(r, blockBytesBuf[:bytecount]); err != nil {
		return blockHead{}, err
	}
	for i := range bytecount {
		n := blockBytesBuf[i]
		sum ^= n
		h.blockBytes |= int(n) << (i * 8)
	}
	if sum != hsum {
		return blockHead{}, ErrCorruptDecodeHeader
	}
	h.blockBits += (h.blockBytes - 1) * 8
	h.newTables = flags&0x80 > 0
	h.lastBlock = flags&0x40 > 0
	return h, nil
}

// readBlockHeader parses block bit limits and dynamic Huffman tables from the stream.
func (d *decoder50) readBlockHeader() error {
	h, err := readBlockHead(d.r)
	if err != nil {
		return err
	}
	if cap(d.payloadBuf) < h.blockBytes {
		d.payloadBuf = make([]byte, h.blockBytes)
	} else {
		d.payloadBuf = d.payloadBuf[:h.blockBytes]
	}
	if _, err = io.ReadFull(d.r, d.payloadBuf); err != nil {
		return err
	}
	d.bitReader.Reset(d.payloadBuf, h.blockBits)
	d.br = &d.bitReader
	d.lastBlock = h.lastBlock
	if h.newTables {
		if err = readCodeLengthTable(d.br, d.codeLength[:], &d.bitlenDecoder); err != nil {
			return err
		}
		if err = d.tables.load(d.codeLength[:]); err != nil {
			return err
		}
	}
	return nil
}
```

Put `blockHead` and `readBlockHead` in `decoder50_parallel.go` (they are shared, but the file that needs the split is the one being created). Run `go test -count=1 -run 'Golden|Decoder50' .` and expect PASS before going on.

- [ ] **Step 2: Write the pipeline tests**

`decoder50_parallel_test.go`:

```go
package rarengine

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// decodeWith returns the outcomes for every fixture with workers decode
// goroutines (1 is the serial path).
func decodeWith(t *testing.T, workers int) []decodeOutcome {
	t.Helper()
	return decodeAll(t, goldenFixtures(t), func(r *Reader) { r.SetWorkers(workers) })
}

// Every fixture decodes identically through the pipeline and the serial
// path: same bytes, same byte counts, same errors, member for member.
// Mutation check: drop the deferred-error rule (surface pendingErr as soon
// as readAhead sees it) and the truncated fixtures differ in byte count.
func TestParallelMatchesSerialOnEveryFixture(t *testing.T) {
	serial := decodeWith(t, 1)
	for _, workers := range []int{2, 4} {
		par := decodeWith(t, workers)
		if len(par) != len(serial) {
			t.Fatalf("workers=%d: %d outcomes, serial %d", workers, len(par), len(serial))
		}
		for i := range serial {
			if par[i].line() != serial[i].line() {
				t.Errorf("workers=%d outcome %d\n par: %s\nserial: %s", workers, i, par[i].line(), serial[i].line())
			}
		}
	}
}

// corruptVariants yields deterministic single-byte corruptions and
// truncations of a fixture. Most land in headers and are refused before
// decoding by both paths; the ones that land in block payloads are what
// this is for.
func corruptVariants(t *testing.T, file string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	// Skip the signature and archive header so variants reach members.
	for i := 64; i < len(data); i += max(1, len(data)/120) {
		v := bytes.Clone(data)
		v[i] ^= 0x5A
		out = append(out, v)
	}
	for i := 128; i < len(data); i += max(1, len(data)/20) {
		out = append(out, bytes.Clone(data[:i]))
	}
	return out
}

func outcomesOf(t *testing.T, archive []byte, workers int) []decodeOutcome {
	t.Helper()
	r := NewReader(volumesOf(archive))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(workers)
	var out []decodeOutcome
	for i := 0; ; i++ {
		e, err := r.NextEntry()
		if errors.Is(err, io.EOF) {
			return out
		}
		o := decodeOutcome{index: i}
		if err != nil {
			o.err = err.Error()
			return append(out, o)
		}
		o.name = e.Header.Name
		var buf bytes.Buffer
		n, rerr := io.Copy(&buf, e)
		o.n = n
		o.sum = fmt.Sprintf("%x", sha256.Sum256(buf.Bytes()))
		if rerr != nil {
			o.err = rerr.Error()
		}
		out = append(out, o)
	}
}

// Damaged input decodes identically too: the same bytes before the error
// and the same error, for byte flips and truncations across the fixture.
// This is the bit-for-bit agreement rule on the inputs that matter.
func TestParallelMatchesSerialOnDamagedInput(t *testing.T) {
	for _, file := range []string{"rar5_solid_bench.rar", "rar5_compress.rar", "rar5_solid_stored_mid.rar"} {
		variants := corruptVariants(t, filepath.Join("testdata", file))
		for vi, v := range variants {
			serial := outcomesOf(t, v, 1)
			par := outcomesOf(t, v, 4)
			if len(serial) != len(par) {
				t.Fatalf("%s variant %d: %d vs %d outcomes", file, vi, len(serial), len(par))
			}
			for i := range serial {
				if serial[i].line() != par[i].line() {
					t.Errorf("%s variant %d outcome %d\nserial: %s\n   par: %s", file, vi, i, serial[i].line(), par[i].line())
				}
			}
		}
	}
}

// A corrupt block header three blocks ahead surfaces only after the blocks
// before it have been replayed: the byte count before the error equals the
// serial path's. Built by corrupting the header checksum byte of a known
// block in the fixture; findBlockOffsets locates block headers by decoding
// serially and recording where each header started in the member's packed
// stream.
func TestParallelDefersReadAheadErrors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rar5_solid_bench.rar"))
	if err != nil {
		t.Fatal(err)
	}
	offsets := blockHeaderOffsets(t, data)
	if len(offsets) < 6 {
		t.Fatalf("need at least 6 blocks, found %d", len(offsets))
	}
	v := bytes.Clone(data)
	v[offsets[4]+1] ^= 0xFF // the checksum byte of the fifth block's header
	serial := outcomesOf(t, v, 1)
	par := outcomesOf(t, v, 4)
	if serial[0].err == "" || !strings.Contains(serial[0].err, ErrCorruptDecodeHeader.Error()) {
		t.Fatalf("setup: serial outcome %q does not report the corrupt header", serial[0].err)
	}
	if serial[0].n == 0 {
		t.Fatal("setup: the serial path delivered nothing before the error, so deferral is unobservable")
	}
	if serial[0].line() != par[0].line() {
		t.Fatalf("deferred error differs\nserial: %s\n   par: %s", serial[0].line(), par[0].line())
	}
}

// blockHeaderOffsets returns the archive offsets of each block header in the
// first compressed member, by reading the member's packed bytes through a
// counting reader while the serial decoder parses block heads.
func blockHeaderOffsets(t *testing.T, archive []byte) []int {
	t.Helper()
	r := NewReader(volumesOf(archive))
	defer r.Close() //nolint:errcheck
	e := firstCompressedMember(t, r)
	// The member's packed data begins where the volume's cursor is now;
	// e.src bottoms out on the volume body. Rather than reach into the
	// volume, locate headers by scanning: decode serially, and after each
	// readBlockHeader, search the archive for the payload bytes just read.
	_ = e
	d, win := r.dec50, r.win
	drain := make([]byte, win.size)
	var offsets []int
	from := 0
	for {
		if err := d.readBlockHeader(); err != nil {
			t.Fatalf("readBlockHeader: %v", err)
		}
		at := bytes.Index(archive[from:], d.payloadBuf)
		if at < 0 {
			t.Fatal("payload not found in archive")
		}
		// The header precedes the payload by 2 + bytecount bytes; bytecount
		// is the smallest byte width that holds the payload length.
		bc := 1
		for len(d.payloadBuf) >= 1<<(8*bc) {
			bc++
		}
		offsets = append(offsets, from+at-2-bc)
		from += at + len(d.payloadBuf)
		if d.lastBlock {
			return offsets
		}
		// Decode the block's symbols so the next header is read from the
		// right position, draining the window after each so it never fills.
		for {
			sym, err := d.tables.main.ReadSym(d.br)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("ReadSym: %v", err)
			}
			if err := d.decodeSymbol(win, sym); err != nil {
				t.Fatalf("decodeSymbol: %v", err)
			}
			_, _ = win.Read(drain)
		}
		d.br = nil
	}
}
```

The `bytes.Index` search for the payload is sound because payloads are at least 12 KB in this fixture and the search starts after the previous payload.

Also add:

```go
// A new-tables block whose code-length table is invalid must fail only
// when replay reaches it, and the blocks before it, decoded against the
// previous tables, must come out intact. The code-length table is at the
// start of the payload after the header, so corrupting the first payload
// byte of a block that carries tables hits it.
func TestNewTablesFailingDoesNotDisturbInFlightBlocks(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rar5_solid_bench.rar"))
	if err != nil {
		t.Fatal(err)
	}
	offsets := blockHeaderOffsets(t, data)
	// Find a block past the first few that carries new tables (flag 0x80).
	target := -1
	for _, off := range offsets[3:] {
		if data[off]&0x80 != 0 {
			target = off
			break
		}
	}
	if target < 0 {
		t.Skip("no later block in the fixture carries new tables")
	}
	bc := int(data[target]>>3)&3 + 1
	v := bytes.Clone(data)
	v[target+2+bc] = 0xFF // first payload byte: the start of the code-length table
	serial := outcomesOf(t, v, 1)
	par := outcomesOf(t, v, 4)
	if serial[0].line() != par[0].line() {
		t.Fatalf("\nserial: %s\n   par: %s", serial[0].line(), par[0].line())
	}
	if serial[0].n == 0 {
		t.Fatal("setup: nothing decoded before the bad tables; choose a later block")
	}
}
```

Add the imports these need (`crypto/sha256`, `fmt`, `os`, `strings`).

- [ ] **Step 3: Run to see them fail**

Run: `go test -count=1 -run 'TestParallel|TestNewTables' .`
Expected: FAIL to compile (`SetWorkers` undefined). Add a temporary stub to `reader.go` for this task only, replaced by the real method in Task 5:

```go
// SetWorkers is defined fully in the next task; this stub lets the
// pipeline tests compile.
func (r *Reader) SetWorkers(n int) { r.workers = n }
```

with a `workers int` field on `Reader`, and in `buildChain` after `r.dec50.init(src, fh.FirstBlock)`:

```go
	r.dec50.setPipeline(r.workers)
```

Run again: expected FAIL with undefined `setPipeline` and the rest.

- [ ] **Step 4: Implement the synchronous pipeline**

`decoder50_parallel.go` (add to the file that already holds `blockHead`):

```go
const (
	maxWorkers         = 8
	maxParallelPayload = 4 << 20
)

type blockPipeline struct {
	workers int

	slots       []*blockJob
	head, count int
	idx         int
	inline      bool

	tables []*tableSet
	inUse  []int
	cur    int

	pendingErr error
	sawLast    bool
	engaged    bool

	codeLength [tableSize5]byte
	bitlen     huffmanDecoder
}

func newBlockPipeline(workers int) *blockPipeline {
	r := 2 * workers
	p := &blockPipeline{
		workers: workers,
		slots:   make([]*blockJob, r),
		tables:  make([]*tableSet, r+1),
		inUse:   make([]int, r+1),
	}
	for i := range p.slots {
		p.slots[i] = &blockJob{
			items: make([]item, itemCap),
			done:  make(chan struct{}, 1),
		}
	}
	for i := range p.tables {
		p.tables[i] = &tableSet{}
		p.tables[i].prewarm()
	}
	return p
}

// setPipeline chooses the decoder for the member being built: the serial
// path for workers <= 1, otherwise a pipeline of min(workers, maxWorkers)
// decode goroutines, created on first use and kept for the Reader's life.
func (d *decoder50) setPipeline(workers int) {
	if workers <= 1 {
		if d.pipe != nil && d.pipe.engaged {
			d.pipe.disengage(d)
		}
		return
	}
	workers = min(workers, maxWorkers)
	if d.pipe == nil || d.pipe.workers != workers {
		if d.pipe != nil {
			d.pipe.drain()
		}
		d.pipe = newBlockPipeline(workers)
	}
	d.pipe.engage(d)
}

func (p *blockPipeline) engage(d *decoder50) {
	p.drain()
	p.head, p.count, p.idx, p.inline = 0, 0, 0, false
	p.pendingErr, p.sawLast = nil, false
	if !p.engaged {
		// Seed from the serial decoder so a member whose first block
		// carries no tables sees what the previous member left, as the
		// serial path would.
		p.cur = p.freeTableSet()
		p.tables[p.cur].copyFrom(&d.tables)
	}
	p.engaged = true
}

func (p *blockPipeline) disengage(d *decoder50) {
	p.drain()
	d.tables.copyFrom(p.tables[p.cur])
	p.engaged = false
}

// drain waits for every job in flight and empties the ring. In this
// synchronous version nothing is ever in flight.
func (p *blockPipeline) drain() {
	for p.count > 0 {
		p.pop()
	}
}

// freeTableSet returns the index of a set no in-flight job references.
// With len(slots)+1 sets and each slot referencing one, there is always
// one.
func (p *blockPipeline) freeTableSet() int {
	for i, n := range p.inUse {
		if n == 0 {
			return i
		}
	}
	panic("rarengine: no free table set") // unreachable by construction
}

// readAhead fills the ring from d.r. A read error is not returned: it is
// recorded and surfaced by fillParallel only once every block before it
// has been replayed, which is when the serial path would have met it.
func (p *blockPipeline) readAhead(d *decoder50) {
	for p.count < len(p.slots) && !p.sawLast && p.pendingErr == nil {
		h, err := readBlockHead(d.r)
		if err != nil {
			p.pendingErr = err
			return
		}
		j := p.slots[(p.head+p.count)%len(p.slots)]
		if cap(j.payload) < h.blockBytes {
			j.payload = make([]byte, h.blockBytes)
		} else {
			j.payload = j.payload[:h.blockBytes]
		}
		if _, err := io.ReadFull(d.r, j.payload); err != nil {
			p.pendingErr = err
			return
		}
		j.bits = h.blockBits
		j.lastBlock = h.lastBlock
		j.resume.Reset(j.payload, h.blockBits)
		if h.newTables {
			if err := readCodeLengthTable(&j.resume, p.codeLength[:], &p.bitlen); err != nil {
				p.pendingErr = err
				return
			}
			next := p.cur
			if p.inUse[p.cur] > 0 {
				next = p.freeTableSet()
			}
			if err := p.tables[next].load(p.codeLength[:]); err != nil {
				// The serial path fails this block at readBlockHeader, after
				// every earlier block was decoded. Record it like any other
				// read-ahead error; the tables that failed to load are in a
				// set no block references.
				p.pendingErr = err
				return
			}
			p.cur = next
		}
		j.tables = p.tables[p.cur]
		p.inUse[p.cur]++
		p.count++
		p.sawLast = h.lastBlock
		p.submit(j)
	}
}

// submit decodes the job. Workers replace this in the next task.
func (p *blockPipeline) submit(j *blockJob) {
	if len(j.payload) > maxParallelPayload {
		// Too big to hold decoded; finish it inline when it reaches the head.
		j.partial = true
		j.n = 0
		j.err = nil
		return
	}
	decodeBlockItems(j)
}

// wait blocks until j is decoded. Synchronous: it already is.
func (p *blockPipeline) wait(j *blockJob) error { return nil }

func (p *blockPipeline) pop() {
	j := p.slots[p.head]
	for i := range p.tables {
		if p.tables[i] == j.tables {
			p.inUse[i]--
			break
		}
	}
	j.tables = nil
	p.head = (p.head + 1) % len(p.slots)
	p.count--
	p.idx = 0
	p.inline = false
}

// fillParallel is fill for an engaged pipeline: stage bytes from the
// oldest block's items until the fill target is reached, reading ahead and
// handing blocks to the workers as slots free up.
func (d *decoder50) fillParallel(win *window) error {
	p := d.pipe
	target := win.fillTarget()
	for win.Available() < target {
		if p.count == 0 {
			p.readAhead(d)
			if p.count == 0 {
				if p.pendingErr != nil {
					return p.pendingErr
				}
				return io.EOF
			}
		}
		j := p.slots[p.head]
		if err := p.wait(j); err != nil {
			return err
		}
		if !p.inline {
			exhausted, err := d.replayItems(win, j, &p.idx, target)
			if err != nil {
				return err
			}
			if !exhausted {
				return nil // target reached mid-block
			}
			if j.err != nil {
				err := j.err
				p.pop()
				return err
			}
			if !j.partial {
				last := j.lastBlock
				p.pop()
				if last {
					return io.EOF
				}
				p.readAhead(d)
				continue
			}
			p.inline = true
		}
		done, err := d.finishBlockInline(win, j, target)
		if err != nil {
			p.pop()
			return mapInnerErr(err)
		}
		if done {
			last := j.lastBlock
			p.pop()
			if last {
				return io.EOF
			}
			p.readAhead(d)
		}
	}
	return nil
}
```

Then in `decoder50.go`:

- add `pipe *blockPipeline` to the struct;
- at the top of `fill`: `if d.pipe != nil && d.pipe.engaged { return d.fillParallel(win) }`;
- in `init`, after `d.br = nil`: `if d.pipe != nil { d.pipe.drain(); d.pipe.engaged = false }` — a new member re-engages through `setPipeline`, so a stored member or a serial member never finds a stale ring. Careful: `setPipeline` runs after `init` in `buildChain`, and `engage` copies `d.tables` into `cur` only when `!p.engaged` was already false, which `init` just made true... Resolve: `init` must NOT clear `engaged`; it only drains. `engage` seeds from `d.tables` only on the first engagement after a serial member (tracked by `engaged == false`, which `setPipeline(workers<=1)` sets through `disengage`). So in `init`: `if d.pipe != nil { d.pipe.drain() }` and nothing else.
- EOF semantics: the serial `fill` returns `io.EOF` when the last block's symbols are exhausted and `d.lastBlock`; `Read` maps that to end of member once the window drains. `fillParallel` returns `io.EOF` under the same condition. When there is pending output in the window, `Read` serves it first because it calls `fill` only when `Available() == 0`; `stageFilterInput` tolerates `io.EOF` the same way. Verify by reading `decoder50.Read` and `stageFilterInput` before changing anything there; nothing should need changing.
- A member abandoned mid-decode: `init` on the next member drains. Stored members: `buildChain` returns `src` without `init`, so the ring keeps stale jobs from an abandoned compressed member until the next compressed member's `init`; harmless in this task (no goroutines), handled in Task 5.

`finishBlockInline`'s oversize case: `submit` set `partial` with `n = 0` and `resume` positioned after the tables, so `finishBlockInline` adopts the tables and decodes the whole block inline. The job's payload buffer for an oversize block is the one allocation this path makes, bounded by the format's 16 MiB and freed when the slot next shrinks... it never shrinks. Bound it: in `readAhead`, when `h.blockBytes > maxParallelPayload`, do not grow `j.payload`; instead set a flag `j.oversize = true` and read the payload into `d.payloadBuf` (the serial buffer), set `j.payload = d.payloadBuf`, and stop reading ahead until this job is popped (`for ... && !p.oversizePending`). Add `oversize bool` to `blockJob` and `oversizePending bool` to the pipeline; `pop` clears it. This keeps the slot's own buffer small and reuses the serial buffer exactly as the serial path would. Write it so; the test below forces it.

- [ ] **Step 5: Oversize block test**

Append to `decoder50_parallel_test.go`:

```go
// A block larger than maxParallelPayload is decoded inline with the serial
// buffer, not held in a slot. Forced by lowering the limit through a test
// hook, since no fixture has a 4 MiB block.
func TestOversizeBlockIsDecodedInline(t *testing.T) {
	saved := parallelPayloadLimit
	t.Cleanup(func() { parallelPayloadLimit = saved })
	parallelPayloadLimit = 16 << 10 // every block in the fixture is "oversize"
	serial := decodeAll(t, []string{filepath.Join("testdata", "rar5_solid_bench.rar")}, nil)
	par := decodeAll(t, []string{filepath.Join("testdata", "rar5_solid_bench.rar")}, func(r *Reader) { r.SetWorkers(4) })
	for i := range serial {
		if serial[i].line() != par[i].line() {
			t.Fatalf("\nserial: %s\n   par: %s", serial[i].line(), par[i].line())
		}
	}
}
```

So `maxParallelPayload` is used through a package variable `var parallelPayloadLimit = maxParallelPayload` that `readAhead` consults. Mutation check: make `readAhead` ignore the limit and the test still passes (bytes agree either way) — so add an assertion that exercises the path: after decoding with the small limit, `r.dec50.pipe.slots[0].oversize` was set at least once; track a counter `p.oversizeBlocks int` incremented in `readAhead` and assert it is > 0 in the test. With the counter, dropping the limit check fails the test.

- [ ] **Step 6: Run all pipeline tests**

Run: `go test -race -count=1 -run 'TestParallel|TestNewTables|TestOversize|Golden' -v .`
Expected: PASS. If `TestParallelMatchesSerialOnDamagedInput` reports a difference, the usual causes are: an error surfaced early (check `pendingErr` handling), `mapInnerErr` not applied on a path, or the `ErrTooManyFilters` ordering from Task 2. Fix the pipeline, never the test.

- [ ] **Step 7: Mutation check on deferral**

In `readAhead`, replace `p.pendingErr = err; return` after `readBlockHead` with `panic(err)`'s opposite: make `fillParallel` return `p.pendingErr` at the top of its loop whenever it is non-nil, before replaying. Run `TestParallelDefersReadAheadErrors`; expect a byte-count difference. Revert.

- [ ] **Step 8: Gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add decoder50.go decoder50_parallel.go decoder50_parallel_test.go reader.go
git commit -m "feat(decoder): read blocks ahead into a ring and replay in order

A ring of block jobs is filled from the member's stream on the caller
goroutine: header, payload, and the Huffman tables when the block
carries them, with each job referencing the table set in force. Jobs
are replayed oldest first. A read-ahead error is held until every block
before it has been replayed, so the caller sees the bytes and then the
error exactly as the serial path delivers them. Blocks are still decoded
on the caller goroutine; the ring is the part the workers will share.

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Workers, `SetWorkers`, Close and Reset

Add the goroutines. The ring and replay do not change; `submit` sends, `wait` receives, and every blocking operation also watches a quit channel that `Reader.Close` closes.

**Files:**
- Modify: `decoder50_parallel.go` (`submit`, `wait`, `drain`, start/stop/restart, worker loop)
- Modify: `reader.go` (`SetWorkers` real doc, `Close` stops, `Reset` restarts)
- Test: `reader_workers_test.go`

**Interfaces:**
- Produces:

```go
// Reader.SetWorkers sets how many goroutines decode a compressed member's
// blocks. n <= 1 is the serial decoder, the default. Takes effect at the
// next member.
func (r *Reader) SetWorkers(n int)

func (p *blockPipeline) start()   // starts p.workers goroutines if not running
func (p *blockPipeline) stop()    // closes quit, waits for the goroutines, marks not running
func (p *blockPipeline) restart() // new quit channel; goroutines start lazily on next engage
```

- [ ] **Step 1: Write the concurrency tests**

`reader_workers_test.go`:

```go
package rarengine

import (
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func goroutinesSettle(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("goroutines: %d, want at most %d", runtime.NumGoroutine(), want)
}

// Close stops the workers and a Close after Close is harmless.
// Mutation check: make stop skip wg.Wait and the goroutine count stays up.
func TestCloseStopsDecodeWorkers(t *testing.T) {
	base := runtime.NumGoroutine()
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	r.SetWorkers(4)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := e.Read(buf); err != nil {
		t.Fatal(err)
	}
	if runtime.NumGoroutine() < base+4 {
		t.Fatalf("workers not running: %d goroutines, baseline %d", runtime.NumGoroutine(), base)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	goroutinesSettle(t, base)
}

// Close from another goroutine while the traversal goroutine is inside a
// Read that waits for a worker: the Read returns ErrReaderClosed and the
// workers exit. The worker is held by a job that never completes until
// released, through the test hook on decodeBlockItems.
// Mutation check: make wait receive on j.done alone and this hangs (the
// test's own timeout catches it).
func TestCloseWhileWaitingForWorkers(t *testing.T) {
	base := runtime.NumGoroutine()
	release := make(chan struct{})
	saved := decodeHook
	decodeHook = func() { <-release }
	t.Cleanup(func() { decodeHook = saved; close(release) })

	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	r.SetWorkers(2)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, e)
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the traversal goroutine block in wait
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("Read after Close = %v, want ErrReaderClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after Close")
	}
	goroutinesSettle(t, base)
}

// A member abandoned with jobs in flight: NextEntry moves on, the next
// compressed member decodes correctly, and no worker is still writing a
// slot the new member reuses (the race detector is the oracle; run with
// -race -count=100).
func TestAbandonedMemberDrainsInFlightJobs(t *testing.T) {
	// Two compressed members in one archive: the far fixtures are single
	// member, so use the solid bench archive twice through Reset.
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(4)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	// Abandon: Reset to the same archive with jobs in flight.
	r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	want := decodeAll(t, []string{filepath.Join("testdata", "rar5_solid_bench.rar")}, nil)
	for i := range want {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("after abandon, NextEntry %d: %v", i, err)
		}
		h := sha256.New()
		n, err := io.Copy(h, e)
		if err != nil {
			t.Fatalf("after abandon, member %d: %v", i, err)
		}
		if n != want[i].n || hex.EncodeToString(h.Sum(nil)) != want[i].sum {
			t.Fatalf("after abandon, member %d differs from the serial decode", i)
		}
	}
}

// Reset revives a closed Reader's pipeline.
func TestResetRevivesWorkersAfterClose(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	r.SetWorkers(2)
	if _, err := r.NextEntry(); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("decode after Reset: %v", err)
	}
}

// SetWorkers is latched per member: changing it mid-member has no effect
// until the next member, and n above maxWorkers is clamped.
func TestSetWorkersTakesEffectAtTheNextMember(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkers(64)
	if r.dec50.pipe != nil {
		t.Fatal("SetWorkers engaged a pipeline for the member already in progress")
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatal(err)
	}
	if _, err := r.NextEntry(); err != nil {
		t.Fatal(err)
	}
	if r.dec50.pipe == nil || r.dec50.pipe.workers != maxWorkers {
		t.Fatalf("next member: pipe=%v, want %d workers", r.dec50.pipe, maxWorkers)
	}
}
```

Imports: add `crypto/sha256`, `encoding/hex`. `decodeHook` is a package-level `var decodeHook func()` in `decoder50_parallel.go`, called by the worker before `decodeBlockItems` when non-nil; it exists for this test only and costs one nil check per block.

- [ ] **Step 2: Run to see them fail**

Run: `go test -count=1 -run 'TestClose|TestAbandoned|TestResetRevives|TestSetWorkers' .`
Expected: compile failure on `decodeHook`, then (after stubbing it) `TestCloseStopsDecodeWorkers` fails on "workers not running".

- [ ] **Step 3: Implement workers and lifecycle**

In `decoder50_parallel.go`, add to `blockPipeline`:

```go
	jobs    chan *blockJob
	quit    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex // guards quit, running, and the start/stop transitions
	running bool
```

`var decodeHook func()`.

```go
func (p *blockPipeline) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return
	}
	if p.quit == nil {
		p.quit = make(chan struct{})
	}
	p.jobs = make(chan *blockJob, len(p.slots))
	p.running = true
	quit, jobs := p.quit, p.jobs
	for range p.workers {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-quit:
					return
				case j := <-jobs:
					if decodeHook != nil {
						decodeHook()
					}
					decodeBlockItems(j)
					j.done <- struct{}{}
				}
			}
		}()
	}
}

// stop ends the goroutines. A worker mid-block finishes that block first
// (bounded: one block), then sees quit. Safe from any goroutine; the
// traversal goroutine blocked in wait is released by the same close.
func (p *blockPipeline) stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	close(p.quit)
	p.running = false
	p.mu.Unlock()
	p.wg.Wait()
}

// restart arms a fresh quit channel so the next engage can start workers.
func (p *blockPipeline) restart() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return
	}
	p.quit = make(chan struct{})
}

func (p *blockPipeline) quitChan() chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quit
}
```

Replace `submit` and `wait`:

```go
func (p *blockPipeline) submit(j *blockJob) {
	if j.oversize {
		j.partial, j.n, j.err = true, 0, nil
		j.done <- struct{}{} // nothing to decode; ready at once
		return
	}
	j.inFlight = true
	select {
	case p.jobs <- j:
	case <-p.quitChan():
		// Closed under us. Mark the job complete with the closed error so
		// wait reports it without blocking.
		j.inFlight = false
		j.err = ErrReaderClosed
		j.done <- struct{}{}
	}
}

func (p *blockPipeline) wait(j *blockJob) error {
	if !j.inFlight && !j.waited {
		<-j.done
		j.waited = true
		return j.err
	}
	if j.waited {
		return nil
	}
	select {
	case <-j.done:
		j.inFlight, j.waited = false, true
		return nil
	case <-p.quitChan():
		return ErrReaderClosed
	}
}
```

Hmm: the above `wait` is tangled. Simplify the job state to one flag, `waited bool`, set in `pop` to false and in `wait` to true after `<-j.done` succeeds; every `submit` path (worker, oversize, closed) eventually sends on `j.done` exactly once, so:

```go
func (p *blockPipeline) wait(j *blockJob) error {
	if j.waited {
		return nil
	}
	select {
	case <-j.done:
		j.waited = true
		return nil
	case <-p.quitChan():
		return ErrReaderClosed
	}
}
```

and `fillParallel` checks `j.err` after `wait` as it already does (a `j.err == ErrReaderClosed` from the closed-submit path then returns through the existing `if j.err != nil` arm after replaying zero items). Use this simpler version; delete the tangled one. `pop` must reset `j.waited = false`.

`drain` with goroutines:

```go
// drain waits for every job in flight, then empties the ring. After a
// stop, a job never picked up has nobody to complete it, so the wait also
// watches quit; its slot is then released without draining its done
// channel, and pop's reset of waited plus the buffered send that may still
// arrive would desynchronise the next use. Guard that: a job whose done
// was never received gets its channel replaced.
func (p *blockPipeline) drain() {
	for p.count > 0 {
		j := p.slots[p.head]
		if !j.waited {
			select {
			case <-j.done:
			case <-p.quitChan():
				j.done = make(chan struct{}, 1)
			}
		}
		p.pop()
	}
}
```

Wait, there is a subtlety: a worker that received the job before quit and is mid-decode will still send on the OLD channel after we replaced it; the old channel is buffered 1 and unreferenced, so the send completes and the channel is garbage. Correct.

`engage` calls `p.start()` after resetting the ring. `setPipeline` creating a new pipeline when the worker count changes must `stop()` the old one first (after `drain()`).

In `reader.go`:

```go
// SetWorkers sets how many goroutines decode a compressed member's blocks.
// n <= 1 is the serial decoder, the default. n > 1 decodes blocks on
// min(n, 8) goroutines while the calling goroutine replays them into the
// window: about 1.4x to 2x faster on compressed members at roughly 1.5x the
// CPU, nothing on stored members. Takes effect at the next member. The
// goroutines live until Close; Reset revives them.
func (r *Reader) SetWorkers(n int) { r.workers = n }
```

In `Close`, after the unlock (the `--- no lock held below this line ---` marker) and before closing volumes: `r.dec50.stopWorkers()` where

```go
func (d *decoder50) stopWorkers() {
	if d.pipe != nil {
		d.pipe.stop()
	}
}
```

`stop` takes only the pipeline's own mutex and `wg.Wait`, never `volMu`, so no lock-order issue. It is the one call from Close into the decoder; it touches no window storage and no ring state (the ring belongs to the traversal goroutine, which `wait`/`submit` release through quit).

In `Reset`, after the new `done` is installed: `r.dec50.restartWorkers()`:

```go
func (d *decoder50) restartWorkers() {
	if d.pipe != nil {
		d.pipe.restart()
	}
}
```

Keep the `Reset` ordering: `severActive` first (as today), and `restartWorkers` after `r.done` is replaced. The abandoned member's jobs are drained by the next `init`.

`init`: `if d.pipe != nil { d.pipe.drain() }` stays from Task 4; with goroutines it now actually waits.

- [ ] **Step 4: Run the concurrency tests, then stress them**

Run: `go test -race -count=1 -run 'TestClose|TestAbandoned|TestResetRevives|TestSetWorkers|TestParallel' .`
Expected: PASS.

Run: `go test -race -count=100 -run 'TestCloseStopsDecodeWorkers|TestCloseWhileWaitingForWorkers|TestAbandonedMemberDrainsInFlightJobs|TestResetRevivesWorkersAfterClose' .`
Expected: PASS, every iteration. A single failure is a real race; do not retry it away. Diagnose with the race report.

- [ ] **Step 5: Mutation checks**

(a) In `stop`, delete `p.wg.Wait()`: `TestCloseStopsDecodeWorkers` must fail on the goroutine count. (b) In `wait`, replace the select with a plain `<-j.done`: `TestCloseWhileWaitingForWorkers` must fail on its 5 s timeout. Revert both.

- [ ] **Step 6: Gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add decoder50.go decoder50_parallel.go reader.go reader_workers_test.go
git commit -m "feat(reader): decode blocks on worker goroutines behind SetWorkers

SetWorkers(n) with n above 1 hands each block to one of min(n, 8)
goroutines while the calling goroutine replays the items in order. The
default stays serial. Close stops the workers and releases a Read that
is waiting on one with ErrReaderClosed; Reset revives them; a member
abandoned mid-decode has its in-flight blocks drained before their slots
are reused.

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Zero-alloc, benchmark, docs

**Files:**
- Test: `reader_workers_test.go` (alloc test), `reader_benchmark_test.go` (parallel benchmark)
- Modify: `CLAUDE.md`, `README.md`

- [ ] **Step 1: Allocation test**

Append to `reader_workers_test.go`:

```go
// Entry.Read allocates nothing in steady state through the pipeline: the
// slots, items, payload buffers and table sets are allocated when the
// pipeline starts, and the first member grows the payload buffers once.
// Mutation check: allocate a fresh item slice per block in decodeBlockItems
// and the count is non-zero.
func TestParallelReadDoesNotAllocate(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	r := NewReader(fileVolumesOf(t, file))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(4)
	// Warm: first member grows every buffer to this archive's block size.
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	allocs := testing.AllocsPerRun(3, func() {
		r.Reset(fileVolumesOf(t, file))
		e, err := r.NextEntry()
		if err != nil {
			t.Fatal(err)
		}
		for {
			_, err := e.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	// Reset and NextEntry allocate for the new volume and header; measure
	// Read alone by subtracting a run that reads nothing.
	base := testing.AllocsPerRun(3, func() {
		r.Reset(fileVolumesOf(t, file))
		if _, err := r.NextEntry(); err != nil {
			t.Fatal(err)
		}
	})
	if allocs-base > 0 {
		t.Fatalf("Read allocated %.0f times per member through the pipeline", allocs-base)
	}
}
```

`fileVolumesOf` opens files and allocates; it runs in both closures so it cancels out. If `allocs-base` is not exactly 0, find the allocation with `go test -run TestParallelReadDoesNotAllocate -memprofile mem.out -memprofilerate 1` and `go tool pprof -sample_index=alloc_objects -top mem.out`; the usual culprit is a closure captured by `go func()` per block (there must be none: goroutines start once) or `j.done <- struct{}{}` on a nil channel.

- [ ] **Step 2: Benchmark**

In `reader_benchmark_test.go`, add next to `BenchmarkDecompress_Solid`:

```go
func BenchmarkDecompress_SolidWorkers(b *testing.B) {
	for _, w := range []int{2, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", w), func(b *testing.B) {
			benchmarkSolid(b, func(r *Reader) { r.SetWorkers(w) })
		})
	}
}
```

Read `BenchmarkDecompress_Solid` first and factor its body into `benchmarkSolid(b, configure func(*Reader))` so both share it exactly; the existing benchmark calls `benchmarkSolid(b, nil)`.

Run unpinned (parallel needs the cores), five interleaved runs:

```bash
go test -c -o /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t6.test .
for i in 1 2 3 4 5; do /home/hobe/.claude/jobs/99a0ece1/tmp/bench-t6.test -test.run XXX -test.bench 'BenchmarkDecompress_Solid' -test.benchtime 1s -test.benchmem; done > /home/hobe/.claude/jobs/99a0ece1/tmp/t6.txt 2>&1
grep Benchmark /home/hobe/.claude/jobs/99a0ece1/tmp/t6.txt
```

Record the serial and the three worker counts in the task report. The fixture is 1.5 MB packed (57 blocks), so per-member overhead is visible; the corpus numbers come from the orchestrator's 157 MB archive, not from this task.

- [ ] **Step 3: Docs**

`CLAUDE.md`: in the architecture section's `decoder50` description add a paragraph:

> **Parallel block decode (`decoder50_items.go`, `decoder50_parallel.go`).** With `Reader.SetWorkers(n)`, n > 1, a compressed member's blocks are read ahead on the traversal goroutine into a ring of `blockJob`s (header, payload, the `tableSet` in force), decoded on min(n, 8) worker goroutines into 8-byte `item`s, and replayed in order by `fillParallel` into the window. The split is: `decodeOffsetBits`/`decodeLengthBits`/`readFilterBits` read what a block's bits determine on their own; `applyMatch`/`applyRepDist`/`applyRepLast`/`queueFilter` do what depends on earlier output — the distance history, a filter's start position, `CopyBytes`'s history bound. The serial path calls both halves in sequence, so the two paths cannot disagree on arithmetic; `TestSerialDecodeMatchesGolden` pins the serial path against `testdata/decode_golden.tsv`, and `TestParallelMatchesSerialOnEveryFixture`/`OnDamagedInput` pin the parallel path against the serial one, including the bytes delivered before an error. A read-ahead error is held in `pendingErr` until every block before it has been replayed. A block over 4 MiB packed, or one whose symbols overflow `itemCap`, is finished inline by `finishBlockInline` from the exact bit reached, with that block's tables adopted. Workers exit on `quit`, which `Reader.Close` closes; a `wait` or `submit` blocked on them selects on it too, so Close cannot strand the traversal goroutine, and `Reset` arms a fresh channel. `init` drains in-flight jobs before a slot is reused. Everything is allocated when the pipeline starts (`TestParallelReadDoesNotAllocate`). Default serial: the gain is on compressed members only, at about 1.5x the CPU.

Also update the "Key files" table with the two new files and the architecture tree's `decoder50` line to mention the pipeline.

`README.md`: next to the `SetMaxWindow` example add:

```go
r.SetWorkers(4) // decode compressed members on four goroutines (default: one)
```

with one sentence on when it helps.

- [ ] **Step 4: Gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add reader_workers_test.go reader_benchmark_test.go CLAUDE.md README.md
git commit -m "test(decoder): pin zero-alloc parallel reads; benchmark and document SetWorkers

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Self-review notes

- Spec invariant 1 (agreement): Tasks 2 (golden), 3 (block-for-block), 4 (every fixture, damaged input, deferred errors, failing tables). Invariant 2 (history bound at replay): `applyMatch` calls `copyMatch`, Task 2/3. Invariant 3 (zero-alloc): Task 6. Invariant 4 (bounded memory): Task 3 overflow, Task 4 oversize. Invariant 5 (Close/Reset/abandon): Task 5. Invariant 6: untouched by construction; the golden and parallel-vs-serial tests cover `Entry`'s verdicts. Invariant 7 (filters in order): items carry filters, `queueFilter` at replay, Task 3; `TestFilter*` existing tests keep pinning the serial side.
- Names used across tasks: `tableSet{main,offset,lowoffset,length}`, `load`, `prewarm`, `copyFrom`; `decodeOffsetBits`, `decodeLengthBits`, `readFilterBits`; `applyMatch`, `applyRepDist`, `applyRepLast`, `queueFilter`; `item`, `itemKind`, `itemCap`, `blockJob{payload,bits,lastBlock,tables,items,n,partial,resume,err,done,oversize,waited}`; `decodeBlockItems`, `replayItems`, `finishBlockInline`, `mapInnerErr`; `blockHead`, `readBlockHead`; `blockPipeline`, `newBlockPipeline`, `engage`, `disengage`, `drain`, `readAhead`, `submit`, `wait`, `pop`, `freeTableSet`, `start`, `stop`, `restart`, `quitChan`, `parallelPayloadLimit`, `oversizeBlocks`, `oversizePending`, `decodeHook`; `decoder50.pipe`, `setPipeline`, `fillParallel`, `stopWorkers`, `restartWorkers`; `Reader.workers`, `SetWorkers`. Task 4's struct listing omits `oversizePending`, `oversizeBlocks` and the Task 5 fields; the text adds them where introduced.
- Review Focus items 1 to 5 each have a named test in the owning task.
