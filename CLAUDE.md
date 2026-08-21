# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`rarengine` is a zero-allocation, stream-oriented RAR5 decompression library in Go. It is designed for high-throughput Usenet downloaders (e.g., `gonzbd`) that decompress RAR5 streams on-the-fly from channels of `io.ReadCloser` volumes.

The public API surface is intentionally small: `NewStreamDecompressor`, `Reset`, `Next`, `Read`, `SetPassword`, `SetVerifyCRC`, `Version`, plus the exported error sentinels and `FileError` that callers match on. Keep it that way — anything new here is a contract this library has to hold forever.

## Commands

```bash
# Build
go build ./...

# Tests (always with race detector before committing)
go test -race ./...

# Run a single test
go test -run TestName ./...

# Benchmarks
go test -bench=. -benchmem ./...

# Fuzz (run locally, not in CI)
go test -fuzz=FuzzHuffman ./...

# Format and resolve imports after every file edit
goimports -w .

# Adopt new language features
go fix ./...

# Lint
go vet ./...
golangci-lint run ./...
```

**Quality gate before every commit** — all five must pass:
```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
```

## Architecture

The decompression pipeline is built as a chain of `io.Reader` wrappers:

```
volumes <-chan io.ReadCloser
  └─ multiVolumePayloadReader   (splices packed bytes across RAR volumes)
       └─ cbcDecryptReader       (AES-256-CBC; RAR5 encrypted files only)
            └─ storeReader / lz50Reader   (method=0: passthrough; method≥1: LZ77+Huffman)
                 └─ fileReader             (byte budget, running CRC, terminal state)
```

`fileReader` (`filereader.go`) is the sole owner of per-file state and the outermost element of the chain: `StreamDecompressor.Read` is a thin delegation to it. It bounds output by the header's declared size rather than an `io.LimitReader`, because it must distinguish "the declared size was reached" from "the stream ended early" — a limit reader reports both as `io.EOF`.

The `Window` (32 MB sliding buffer, `window.go`) is allocated once in `NewStreamDecompressor` and shared by `storeReader`/`lz50Reader`. `Reset(false)` skips zeroing the buffer; eliminating the zero-loop removed an 81% CPU-time bottleneck.

Skipping the clear is safe only because `CopyBytes` refuses to read behind the history actually written since that reset — `Window.historyLen()`, derived from `w` plus the `wrapped` lap flag. Without that bound a crafted stream can name a back-reference distance larger than the bytes its file has produced and read out the previous file's plaintext, which is still physically present in the buffer. The bound is load-bearing: it is what makes the missing memclr a performance choice rather than an information leak.

### Key files

| File | Role |
|---|---|
| `decompressor.go` | `StreamDecompressor` — public API, volume stitching, AES decryption, reader composition |
| `filereader.go` | `fileReader` — sole owner of per-file state; byte budget, running CRC, terminal error |
| `header.go` | RAR5 block/file/archive header parsing; `sanitizePath` for traversal protection |
| `decoder50.go` | LZ77 + Huffman decode loop (RAR5 method 1–5) |
| `huffman.go` | 10-bit direct-lookup Huffman table (do not replace with tree walk) |
| `bit_reader.go` | MSB-first bit reader; fetches up to 56 bits per call (bit-order contract is load-bearing) |
| `window.go` | 32 MB sliding LZ77 history; `Reset(bool)` — `false` skips memclr |
| `filters.go` | Post-decompression SIMD filters (E8/ARM branch relocation, delta) |
| `vint.go` | RAR5 variable-length integer encoding |

### Concurrency model

The library is **not concurrently safe** within a single `StreamDecompressor` instance. Files within a single archive are decoded sequentially. See `TODO.md` for the analysis of when file-level parallelism is feasible (non-solid multi-file archives only).

### Zero-allocation invariants

- Do not instantiate `StreamDecompressor` inside a loop — use `Reset(newChan)` to reuse the 32 MB window.
- Do not introduce heap allocations inside `Next()` or `Read()` without a benchmark justifying the regression.
- Never reintroduce a zeroing loop on the window history buffer.

## Security Constraints

- `sanitizePath` in `header.go` is mandatory for all archive-internal filenames — do not bypass it.
- The rar-bomb guard (`UnpackedSize > 1000 * PackedSize` for files > 1 MB) must not be weakened or removed without explicit user approval.
- The window history bound in `CopyBytes` (`distance > w.historyLen()`) must not be weakened or removed without explicit user approval. It is what keeps the deliberately-uncleared history buffer from being readable across files — see `Window.wrapped` in `window.go`, which also enumerates the write paths that must maintain it.
- AES key material (password, derived key bytes, salt) must never appear in error messages or log output.
- A file must never terminate cleanly without either meeting its declared `UnpackedSize` or reporting why not. `fileReader.finish` is the only place that decides, and `ErrTruncatedFile` must not be made to satisfy `errors.Is(err, io.EOF)` — callers loop until `io.EOF`, so that would restore the silent-truncation bug it exists to prevent.
- A file's terminal error is durable for that file: once `fileReader.done` is set, `Read` returns it instead of producing bytes. Do not add a path that clears it short of `begin` or `clear`, or a caller that keeps reading will see a failure decay back into success.
- **A header flag must never be able to switch verification off.** Every flag is attacker-supplied and none is cross-checked against what the entry actually contains, so gating the checksum on `IsDir` let a crafted archive deliver arbitrary bytes under a header claiming to be a directory. Gate on values this code enforces — the produced size — not on what the archive says about itself. Where a digest genuinely cannot be checked (`UseMac`, which selects a key-derived MAC), fail with `ErrChecksumUnsupported` rather than completing silently; only `SetVerifyCRC(false)` may turn verification off, because that is the caller's decision rather than the archive's.
- **Sizes are validated where they are decoded.** A RAR5 size vint carries 70 bits and RAR3 composes a size from two attacker-chosen halves, so either can set the sign bit of the `int64`. A negative size passes every "have we produced enough yet" comparison and panics the process at the slice clamp in `fileReader.Read`. Both parsers reject negative sizes, and `Read` tests `remaining <= 0` as the backstop.
- **Never let a block header be parsed out of a previous file's payload.** Resynchronising header parsing onto unread payload lets a crafted archive surface a fabricated file entry from `Next()` — name, size and metadata all attacker-chosen, and the header CRC32 is no obstacle because the attacker computes it. This is not only a truncation concern: a block may declare more packed bytes than its file's `UnpackedSize`, so a file that completes *successfully* can still leave a well-formed header sitting in its own payload. `endFile` drains the packed cursor on every terminal path, not just the failing ones.
- **Refusing a file means dropping its payload, whatever the reason for the refusal.** Traversal continues after a refusal — the caller can and does call `Next()` again — so a refused block that keeps its payload supplies the next "file". This covers every `ParseFileHeader`/`ParseRAR3FileHeader` failure and the rar-bomb guard, in `processHeader` and `processVolumePayloadHeader`, in both engines. Do not narrow it to particular errors: which field an archive corrupts is the archive's choice, and keying the discard on one named error left the same hole reachable through all the others. The block header is CRC-checked before any of these run, so `h.DataSize` is trustworthy even when the file-level fields are not.
- **A `FileError` is a promise that the stream is standing on the next block header, and only a completed drain may make it.** `markContinuable` in `filereader.go` is the only place one is constructed, and it demands proof: `packedCursor.settled()`, meaning the count reached zero by being *read*. It is not `owed() == 0` — `invalidate` zeroes the count without reading, and the volume-advance path invalidates before it learns whether a next volume exists, so every failure there (a header failing its CRC, a refused header, a closed channel) leaves the count at zero with the stream parked wherever the failed read stopped. Gating on the count alone let a crafted archive pick that offset through the size vint of a header it knew would be rejected, and get a fabricated entry back from the next `Next()`. Do not add a second construction site, and do not widen the condition to any state that `invalidate` can also produce.
- **Damage is recorded from what happened to the file, never from the error the caller receives.** `sd.damaged` means "the window holds something other than what a solid successor's back-references assume". Two places set it, for three reasons, and all three are needed. `finishCurrentFile` records what `endFile` saw: the file ended short, so bytes are missing, or it failed its CRC32, so the bytes it wrote are wrong. `refuse` records the third: a file refused before it decoded contributes nothing, and at the `processHeader` sites it never reaches `fileReader` at all. The shortfall from a refused or short file sits INSIDE what `CopyBytes` bounds by, so the window guard cannot catch it. Deriving it from whether a `FileError` came back answers a different question — "may the caller resume?" — and left every non-continuable short file (a truncated volume, a failed drain) recorded as undamaged, so a solid file opening the next volume decoded against history its predecessor never wrote. A short file damages the window whatever the caller is told about it.
- **A per-file header flag must be re-checked on every volume advance, not only at admission.** A RAR3 file's header is parsed again on each volume, and that path builds no reader — it repoints the packed cursor and feeds the bytes into the chain the first block established. So a flag that was absent on the first block and present on a continuation changed nothing: a member whose continuation claimed encryption had that volume's bytes delivered verbatim as content, with a nil error and a header reporting `Encrypted` false — quieter than the mismatch the same archive produced when the flag was set up front. Both `processHeader` and `processVolumePayloadHeader` carry the encryption guard for this reason. The two sites need different primitives, and the reason is not the one it first appears to be. `refuseFile` drives `sd.discard` itself, so it would settle its drain at either site — nothing mechanical stops it mid-file. What stops it is that a file is still active there: an error built at the volume-advance site is laundered through `endFile`'s verdict and reaches the caller as the `*FileError` `refuseFile` constructed, promising the stream is standing on the next block header when `nextVolumePayload` has just abandoned the packed cursor. So `refuseFile` at admission, `refuse` mid-file — and a test must pin the distinction, because swapping them leaves the rest of the suite green.
- **A flag's name is not evidence of its value.** `FileHeader.Encrypted` was derived from RAR3's `0x0400`, which is `LHD_SALT` — it says eight salt bytes follow the name, a statement about header layout. `LHD_PASSWORD` is `0x0004`. Every honest RAR 3.x archive sets both, so the two were indistinguishable in every test and fixture, and only a crafted archive separates them: one setting `LHD_PASSWORD` alone was encrypted, reported `Encrypted` false, and was decoded as though its ciphertext were content. The RAR3 flags now have named constants in `header_rar3.go` and the guard tests both bits, since either alone is a claim of encryption.
- **No block's declared payload survives into the next header read, and the accounting is by default rather than by obligation.** `DataSize` is read from a header flag with no restriction on block type — RAR5 whenever `HeaderFlagHasData` is set, RAR3 whenever `longBlock` is — so *any* block may declare payload, not only a file. Whatever fails to consume it leaves the next header to be parsed out of attacker-chosen bytes. This was written as a per-case obligation three times and forgotten three times, which is why the dispatchers now invert it: a `case` that does nothing falls out of the switch to `dropDeclaredPayload`, and only a case that has handled the payload itself returns early. There are exactly three reasons to return, each carrying a comment at its site — the file claims the payload (`packed.repoint` owns it), a refusal already discarded it (`refuse`/`refuseFile`/`admitFile`), or the volume advanced and took it away (terminator/end). **The discriminator is "has this path already discarded?", never "is the count different?"** — `refuse(h.DataSize, …)` discards the *same* count and must still return, and `admitFile` discards three frames down while reading exactly like plain error propagation. Errors decided inside a switch are recorded in `cause` and returned after the discard, because refusing a block must still drop its payload. The failure mode is inverted along with the control flow: a forgotten discard used to leak attacker bytes silently, while a forgotten return now over-consumes and surfaces as a header CRC failure — except at the two sites that `repoint` and return a reader, where it silently truncates a file mid-volume, which is why those two carry the longest comments.
- **The terminator exemption rests on `nextVolume` clearing `sd.currentVol`, not on `Close`.** The terminator and end-of-archive cases deliberately do not discard, because the stream has moved on — but `Next()` re-enters the engine whenever `currentVol` is non-nil, and `nextVolume` used to return `ErrNoNextVolume` on a closed channel with the volume still in place. A terminator carrying payload followed by a closed channel then had the next header parsed out of that payload. `Close` is no defence: the volumes are caller-supplied and `io.NopCloser`, whose `Close` does nothing, is a mainstream choice. Every failure exit in `nextVolume` therefore clears `currentVol` — including the `detectVersion` one, where leaving a partially-consumed volume with `sd.engine` still nil let a caller's retry panic on a nil interface. A test must model a volume whose `Close` does not stop reads, or it passes against the broken code.
- **A refusal that cannot discard must end traversal, not merely report.** Every refusal in these engines drops the offending block's payload and so leaves the stream standing on the next header, which is what makes it safe for the caller to keep calling `Next()`. `ErrRAR3UnmeasurableSubBlock` is the one refusal that cannot: the byte count it would need is exactly what it failed to read, so the stream stays parked at the start of attacker-chosen bytes. Reporting it without recording `rar3Engine.fatal` left the retry that `Next()`'s own doc comment invites reading its next header out of that payload — the same fabrication the discard rule exists to prevent, reintroduced by the code that added the rule. A new refusal path must therefore answer both questions: what drops the payload, and if nothing can, what stops traversal.
- **A RAR3 subblock declaring `lhdLarge` is refused, not discarded by declared length.** Subblock types carry the file-header layout, so `lhdLarge` puts the high 32 bits of the packed size inside a header no dispatcher parses; only the low half reaches `h.DataSize`. Discarding the declared length would skip less than the block occupies — and unrar, which composes both halves, would disagree about which entries the archive contains. The check is scoped to the subblock types on purpose: `lhdLarge` is `0x0100`, which on a main header is `mhdFirstVolume` and entirely ordinary, so testing the bit alone refuses honest archives.
- **The packed remainder is tracked per volume, never captured once, and never read from a closed volume.** `packedCursor` (in `decompressor.go`) owns the count; `repoint` and `invalidate` are the only mutations and `drain` the only consumption. Both engines repoint it on each volume advance so it always describes the volume being read — a count captured at file start goes stale the moment a file crosses a boundary, and discarding a stale count consumes a *later* volume's legitimate header bytes, reintroducing the fabrication above by another route. `nextVolumePayload` must `invalidate` before calling `nextVolume`, which closes the current volume before it can discover whether a next one exists: a count left standing there is later drained out of a closed, caller-supplied `io.ReadCloser`. Pass the cursor to `endFile` at the call site rather than storing it — read at the point of use it is current by construction.

## Integration Testing

`integration_test.go` runs differential oracle tests against the system `unrar` binary. Test fixtures live in `testdata/`. The fuzz target for the Huffman decoder is in `huffman_test.go` (`FuzzHuffman`).
