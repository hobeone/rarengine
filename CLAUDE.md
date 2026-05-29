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
                 └─ io.LimitReader(fh.UnpackedSize)
```

The `Window` (32 MB sliding buffer, `window.go`) is allocated once in `NewStreamDecompressor` and shared by `storeReader`/`lz50Reader`. `Reset(false)` skips zeroing the buffer — safe because LZ77 only reads bytes within the current write pointer; eliminating the zero-loop removed an 81% CPU-time bottleneck.

### Key files

| File | Role |
|---|---|
| `decompressor.go` | `StreamDecompressor` — public API, volume stitching, AES decryption, reader composition |
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
- AES key material (password, derived key bytes, salt) must never appear in error messages or log output.

## Integration Testing

`integration_test.go` runs differential oracle tests against the system `unrar` binary. Test fixtures live in `testdata/`. The fuzz target for the Huffman decoder is in `huffman_test.go` (`FuzzHuffman`).
