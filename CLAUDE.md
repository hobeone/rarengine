# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`rarengine` is a zero-allocation, stream-oriented RAR5 decompression library in Go. It is designed for high-throughput Usenet downloaders (e.g., `gonzbd`) that decompress RAR5 streams on-the-fly from channels of `io.ReadCloser` volumes.

The public API surface is intentionally small: `NewStreamDecompressor`, `Reset`, `Next`, `Read`, `SetPassword`.

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
       └─ cbcDecryptReader       (AES-256-CBC; only present for encrypted files)
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
- **Never let a block header be parsed out of a previous file's payload.** `fileReader` sees only the decompressed side and stops at the declared size, so a file that ends short leaves an unknown number of *packed* bytes in the stream. `endFile` therefore reports a failure rather than allowing traversal to continue in that case, and any path that refuses a file after reading its block header must drop that file's payload first (as `processHeader` does for `ErrUnpSizeUnknown`, using the CRC-checked `h.DataSize`). Resynchronising header parsing onto unread payload lets a crafted archive surface a fabricated file entry from `Next()`. Making short files skippable requires the engines to drain the packed remainder, which is tracked separately.

## Integration Testing

`integration_test.go` runs differential oracle tests against the system `unrar` binary. Test fixtures live in `testdata/`. The fuzz target for the Huffman decoder is in `huffman_test.go` (`FuzzHuffman`).
