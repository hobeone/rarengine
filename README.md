# rarengine

`rarengine` is a custom, high-speed, zero-allocation, stream-oriented RAR5 decompression engine written from scratch in Go. 

Designed specifically for high-throughput Usenet downloaders (like `gonzbd`), `rarengine` decompresses RAR5 streams on-the-fly directly from network/Go channels and sliding window buffers, achieving maximum CPU efficiency and maintaining a strictly flat memory footprint.

---

## Key Features

- **Zero-Allocation Pipeline**: Reuses a single `Reader` instance and its pre-allocated 32MB sliding window across streams via `Reset`, keeping steady-state allocations minimal.
- **Process In-Process**: Runs entirely within Go—no slow C++ `unrar` binary subprocess forks or shell pipeline parsing.
- **Spec Conformance**: Fully audited and tested for strict conformance to the official RAR 5.0 technote specifications.
- **Differential Oracle Tested**: Verified byte-for-byte against the system-installed canonical `unrar` binary for standard, compressed, solid, and password-encrypted RAR5 archives.
- **Robust Security Boundaries**:
  - **Path Sanitization**: Dynamic, OS-independent path sanitization neutralizes directory traversal exploits (strips relative upward `..` and absolute paths safely).
  - **Rar-Bomb Protection**: Aborts decompression instantly when file expansion ratios exceed `1000x` for files larger than `1MB`.
  - **Bitstream Fuzzing**: Huffman decoder fuzzed with native Go `testing.Fuzz` to prevent crashes or infinite loops on malformed payloads.

---

## Installation

```bash
go get github.com/hobeone/rarengine
```

---

## Usage Example

### Sequential Streaming Decompression (Tar-like Reader)

```go
r := rarengine.NewReader(volumes)
r.SetPasswords([]string{"first-guess", "second-guess"})

for {
	e, err := r.NextEntry()
	if err != nil {
		if errors.Is(err, io.EOF) {
			break
		}
		return err // the archive stopped being parseable
	}
	if e.Header.IsDir {
		_ = e.Close()
		continue
	}
	// This example's policy accepts content the library could not verify --
	// see "Unverifiable checksums" below. It has to be filtered at both sites:
	// io.Copy surfaces the verdict from Read, so without the first filter a
	// fully delivered member is logged as skipped.
	//
	// Note what "skipping" can and cannot mean here. Read returns its verdict
	// alongside the final bytes, and io.Copy writes those bytes before it
	// returns the error -- so by the time you see ErrCRCMismatch or
	// ErrChecksumUnsupported, dst already holds the whole member. Rejecting it
	// means truncating, deleting, or otherwise rolling back dst yourself.
	if _, err := io.Copy(dst, e); err != nil &&
		!errors.Is(err, rarengine.ErrChecksumUnsupported) {
		log.Printf("skipping %s: %v", e.Header.Name, err)
	}
	// Close reports the member's verdict. A member that failed does not end
	// the archive: call NextEntry again.
	if err := e.Close(); err != nil &&
		!errors.Is(err, rarengine.ErrChecksumUnsupported) {
		log.Printf("%s: %v", e.Header.Name, err)
	}
}
```

`NextEntry`'s errors are archive-level only — the volumes channel closed, a
block header would not parse, the format is unsupported. A per-member verdict
(a short read, a CRC mismatch, a rar-bomb refusal) never comes back from
`NextEntry`; it comes from the `Entry` itself, via `Read` or `Close`. One
member failing does not end the archive: `NextEntry` is still safe to call
again to reach the members behind it.

### High-Throughput Reuse (Zero-Allocation Reset)

```go
// Reset the reader to process a new set of volumes, reusing the existing
// 32MB sliding window memory:
r.Reset(newVolumesChan)
```

### Encryption

Encryption is supported for RAR5 only. The two failures it can produce differ
in blast radius. An archive whose block headers are themselves encrypted, and
whose password cannot be resolved, ends the traversal: the headers that would
name the remaining members are ciphertext, so there is nothing to continue to.
A member whose *continuation* block claims encryption its first block did not
costs only that member (`ErrCorruptFileHeader`) — the stream is still standing
on a real block boundary, so the archive stays readable past it.

### Unverifiable checksums

Every member that produces bytes is verified against the CRC32 its header
records. Three archive classes carry no CRC32 to compare against — an
encrypted file whose digest is a key-derived MAC (`UseMac`), an archive
written with `rar -htb` (BLAKE2sp only), and a header recording no digest at
all — and all three report `ErrChecksumUnsupported` from `Read`/`Close`.

The content is still delivered; the error says a check could not be made, not
that the bytes are wrong. The error message names which of the three it was, so
a log line distinguishes `rar -htb` from a header with no digest at all.

A caller whose policy accepts unverifiable content filters the sentinel at
**both** call sites. `Entry.Read` returns the verdict alongside the member's
final bytes, so `io.Copy` and `io.ReadAll` surface it too — filtering only at
`Close` fails the copy instead:

```go
if _, err := io.Copy(dst, e); err != nil &&
	!errors.Is(err, rarengine.ErrChecksumUnsupported) {
	return err
}
if err := e.Close(); err != nil &&
	!errors.Is(err, rarengine.ErrChecksumUnsupported) {
	return err
}
```

A caller that *rejects* unverifiable content drops both filters — and must
then roll `dst` back. `io.Copy` writes the bytes it was given before returning
the error that came with them, so `dst` holds the complete member by the time
any verification failure is visible. This is true of `ErrCRCMismatch` as well:
no verdict in this library can be delivered before the content it describes.

There is no way to switch verification off and get the content regardless.

### RAR7 archives

RAR 7.0 raised the unpack-version field in each file header and changed nothing
else a reader can see from outside it — the signature, block framing and vint
encoding are identical to RAR5. A member declaring any version other than 0
(RAR 5.0) is refused with `ErrUnsupportedFormat`, naming the version.

That refusal is per-member, not archive-level: it arrives through the `Entry`,
and `NextEntry` is still safe to call again for the members behind it.

### RAR3 archives

`rarengine` is RAR5 only. A RAR3 signature is recognised so it can be refused
by name — `ErrUnsupportedFormat`, before any per-member parsing runs — and
nothing past the signature is parsed. A caller that needs to inspect a RAR3
archive should hand it to `unrar`.

---

## Benchmarks

Benchmarks are run using:
```bash
go test -bench=. -benchmem
```

On an **AMD Ryzen 9 9950X3D** CPU, the decompressor achieves the following performance metrics:

```
BenchmarkFilterExecution-32          1397302      866.8 ns/op                    0 B/op    0 allocs/op
BenchmarkDecompress_Store-32         2262195      525.2 ns/op   28.56 MB/s    1000 B/op   22 allocs/op
BenchmarkDecompress_Compress-32      1259260      956.2 ns/op   39.74 MB/s    1696 B/op   37 allocs/op
BenchmarkDecompress_Solid-32              100  11412298 ns/op  459.41 MB/s    3454 B/op  141 allocs/op
BenchmarkReaderResetReusesWindow-32  1777514      680.2 ns/op                1096 B/op   26 allocs/op
```

*(`BenchmarkReaderResetReusesWindow` reuses a single `Reader` and its 32MB sliding window across archives via `Reset`, instead of allocating a fresh window per archive.)*

---

## Security

Please report security issues or concerns. Decompression exploits (corrupt payloads, directory traversals, and decompression bombs) are guarded proactively by design.

---

## License

This project is licensed under the MIT License.
