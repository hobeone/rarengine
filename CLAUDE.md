# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`rarengine` is a zero-allocation, stream-oriented RAR5 decompression library in Go. It is designed for high-throughput Usenet downloaders (e.g., `gonzbd`) that decompress RAR5 streams on-the-fly from channels of `io.ReadCloser` volumes.

The public API surface is intentionally small: `NewReader`, `Reset`, `NextEntry`, `SetPasswords`, plus `Entry`'s `Read`/`Close`, and the exported error sentinels callers match on. Keep it that way — anything new here is a contract this library has to hold forever.

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

```
volumes <-chan io.ReadCloser
  └─ Reader          traversal: volumes, blocks, member admission, password
       └─ volume     one volume's bytes and the position within them
       └─ Entry      one member: reader chain, byte budget, CRC, verdict
            └─ decoder50 / storeReader
                 └─ cbcDecryptReader (if encrypted)
                      └─ multiVolumePayloadReader
```

`Reader` (`reader.go`) owns traversal only: which volume, which block, whether a member may begin. It does not own where the stream is — `volume` (`volume.go`) does, one instance per RAR volume, constructed fresh on every advance so a stale read position cannot outlive the volume it describes. It does not own how a member ended — `Entry` (`entry.go`) does: byte budget, running CRC, and a terminal verdict delivered by both `Read` and `Close` (`Close` reports `nil` on success). `splice.go` stitches a member's payload across a volume boundary; `crypto.go` holds the AES-256-CBC/PBKDF2 primitives; `errors.go` holds the exported sentinels.

The `Window` (32 MB sliding buffer, `window.go`) is allocated once in `NewReader` and shared by `storeReader`/`lz50Reader`. `Reset(false)` skips zeroing the buffer; eliminating the zero-loop removed an 81% CPU-time bottleneck.

Skipping the clear is safe only because `CopyBytes` refuses to read behind the history actually written since that reset — `Window.historyLen()`, derived from `w` plus the `wrapped` lap flag. Without that bound a crafted stream can name a back-reference distance larger than the bytes its file has produced and read out the previous file's plaintext, which is still physically present in the buffer. The bound is load-bearing: it is what makes the missing memclr a performance choice rather than an information leak.

### Key files

| File | Role |
|---|---|
| `reader.go` | `Reader` — public API, traversal, block dispatch, password resolution |
| `volume.go` | `volume` — one RAR volume's byte stream and position within it |
| `entry.go` | `Entry` — sole owner of per-member state; byte budget, running CRC, terminal verdict |
| `splice.go` | splices a member's packed bytes across volumes |
| `crypto.go` | AES-256-CBC / PBKDF2 primitives |
| `errors.go` | exported error sentinels |
| `header.go` | RAR5 block/file/archive header parsing; `sanitizePath` for traversal protection |
| `decoder50.go` | LZ77 + Huffman decode loop (RAR5 method 1–5) |
| `huffman.go` | 10-bit direct-lookup Huffman table (do not replace with tree walk) |
| `bit_reader.go` | MSB-first bit reader; fetches up to 56 bits per call (bit-order contract is load-bearing) |
| `window.go` | 32 MB sliding LZ77 history; `Reset(bool)` — `false` skips memclr; `BeginFile`/`MarkIncomplete` own solid-history damage |
| `filters.go` | Post-decompression SIMD filters (E8/ARM branch relocation, delta) |
| `vint.go` | RAR5 variable-length integer encoding |

### Concurrency model

The library is **not concurrently safe** within a single `Reader` instance. Files within a single archive are decoded sequentially. See `TODO.md` for the analysis of when file-level parallelism is feasible (non-solid multi-file archives only).

### Zero-allocation invariants

- Do not instantiate `Reader` inside a loop — use `Reset(newChan)` to reuse the 32 MB window.
- Do not introduce heap allocations inside `NextEntry()` or `Entry.Read()` without a benchmark justifying the regression.
- Never reintroduce a zeroing loop on the window history buffer.

## Security Constraints

Structurally enforced — one sentence each, because a rule the type holds does not need prose telling a reader to hold it:

- Never let a block header be parsed out of a previous file's payload: `volume.next()` skips before reading, and the traversal has no other way to read a header.
- No block's declared payload survives into the next header read: same mechanism — the skip is unconditional and knows nothing about why a block was not claimed.
- Refusing a file means dropping its payload, whatever the reason for the refusal: same mechanism.
- The packed remainder is tracked per volume, never captured once, never read from a closed volume: `volume.body` is a field of `volume`, and an advance constructs a new `volume` rather than repointing one, so a stale count is unrepresentable.
- Trailing continuation blocks of an abandoned multi-volume file are cleanly drained: `Reader.NextEntry` discards headers where `!fh.FirstBlock`, and `volume.next()` drains their bodies automatically.
- A file's terminal error is durable for that file: `Entry.done`, set once, is returned by both `Read` and `Close`.

Carried forward — still a runtime guard, still needs a test:

- `sanitizePath` in `header.go` is mandatory for all archive-internal filenames — do not bypass it. Applied in the parsers rather than at a write site, so every `FileHeader.Name` this library emits is already safe; this is defence in depth for a consumer that writes `fh.Name` directly, at the cost of destroying the evidence that an archive attempted traversal. The consumer that calls `Create` still owns the authoritative check — a library that writes no files cannot commit a traversal.
- The rar-bomb guard (`UnpackedSize > 1000 * PackedSize` for files > 1 MB) must not be weakened or removed without explicit user approval. It is now expressed as a terminal `Entry` (`terminalEntry` in `reader.go`), not a `refuse` call.
- The window history bound in `CopyBytes` (`distance > w.historyLen()`) must not be weakened or removed without explicit user approval. It is what keeps the deliberately-uncleared history buffer from being readable across files — see `Window.wrapped` in `window.go`, which also enumerates the write paths that must maintain it.
- AES key material (password, derived key bytes, salt) must never appear in error messages or log output. Discipline, not structure, scoped to `crypto.go`.
- A file must never terminate cleanly without either meeting its declared `UnpackedSize` or reporting why not. `Entry.finish` is the only place that decides, and `ErrTruncatedFile` must not be made to satisfy `errors.Is(err, io.EOF)` — callers loop until `io.EOF`, so that would restore the silent-truncation bug it exists to prevent.
- **A header flag must never be able to switch verification off.** Every flag is attacker-supplied and none is cross-checked against what the entry actually contains, so gating the checksum on `IsDir` let a crafted archive deliver arbitrary bytes under a header claiming to be a directory. `Entry.verifyChecksum` gates on `e.size == 0` — the produced size, which this type enforces — never on `IsDir`, which the archive asserts and nothing cross-checks; `TestCRCVerificationIgnoresIsDir` pins this. Where a digest genuinely cannot be checked (`UseMac`, which selects a key-derived MAC), it fails with `ErrChecksumUnsupported` rather than completing silently. Verification is now unconditional: `SetVerifyCRC` is gone, and nothing a header says can turn it off.
- **Sizes are validated where they are decoded.** A RAR5 size vint carries 70 bits and RAR3 composes a size from two attacker-chosen halves, so either can set the sign bit of the `int64`. A negative size passes every "have we produced enough yet" comparison and panics the process at the slice clamp in `Entry.Read`. Both parsers reject negative sizes, and `Read` tests `remaining <= 0` as the backstop.
- **Damage is recorded from what happened to the file, never from the error the caller receives.** The window's `incomplete` flag means "the window holds something other than what a solid successor's back-references assume". `Window.MarkIncomplete` is the sole setter, called from two places: `Reader.finishActive`, from the outcome it observes on the member just abandoned (`e.short()`, or a `done` that is neither `io.EOF` nor `ErrChecksumUnsupported`), and `Reader.dispatch`'s refusal paths — a rar-bomb, a `BeginFile` failure, a failed `buildChain` — where a file is refused before it ever reaches `Entry`. A file refused before it decoded contributes nothing, same as one that ended short or failed its CRC32: all three damage the window whatever the caller is told about it.
- **A per-file header flag must be re-checked on every volume advance, not only at admission.** This now applies to RAR5: `Reader.nextVolumePayload` asserts `fh.Encrypted == e.Header.Encrypted` on every continuation block, returning `ErrCorruptFileHeader` on mismatch, so a member whose continuation claims encryption its first block did not cannot have that volume's bytes delivered verbatim as content.
- **A flag's name is not evidence of its value.** `FileHeader.Encrypted` was derived from RAR3's `0x0400`, which is `LHD_SALT` — it says eight salt bytes follow the name, a statement about header layout. `LHD_PASSWORD` is `0x0004`. Every honest RAR 3.x archive sets both, so the two were indistinguishable in every test and fixture, and only a crafted archive separates them: one setting `LHD_PASSWORD` alone was encrypted, reported `Encrypted` false, and was decoded as though its ciphertext were content. The RAR3 flags have named constants in `header_rar3.go` (`lhdPassword`, `lhdSalt`) and `ParseRAR3FileHeader` derives `Encrypted` from `lhdPassword` alone — a caller that wants full encryption-claim detection across both bits should check `Encrypted || len(Salt) > 0`.
- **A malformed archive header ends traversal.** `Reader.dispatch` wraps a failed `ParseArchiveHeader` as `ErrCorruptArchiveHeader` (the underlying failure, typically `ErrTruncatedVint`, is still reachable through `errors.Is`) and latches it on `Reader.fatal`; every later `NextEntry` call returns it again without touching `r.vol`. `Reset` clears the latch. `io.EOF` and `ErrNoNextVolume` deliberately do NOT latch — they are ordinary end-of-archive signals, not failures — but note `ErrNoNextVolume` means something different depending on where it surfaces: reaching a read in progress means that member is unfinished, reaching `NextEntry` means the archive is over.
- **A refusal that cannot discard payload must end traversal, not merely report.** This constraint no longer belongs to one engine — the RAR3 engine it was originally written about is deleted — so it is now about any traversal component that can leave the stream standing on unread, attacker-chosen bytes. Two mechanisms enforce it today: `volume.err`, sticky once a `volume.next()` call fails partway through either the payload skip or the following header read, so the same failure is returned on every later call without `v.rc` being touched again; and `Reader.fatal`, latched by `NextEntry` for every archive-level failure that leaves `r.vol` non-nil after it (a corrupt archive header, a header-encryption failure). Both exist because a stream position that cannot be vouched for must never be retried into — the RAR3-specific version of this rule was lost once precisely because it was written as though it applied to one format's engine.

## Integration Testing

`integration_test.go` runs differential oracle tests against the system `unrar` binary. Test fixtures live in `testdata/`. The fuzz target for the Huffman decoder is in `huffman_test.go` (`FuzzHuffman`).
