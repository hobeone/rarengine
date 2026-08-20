# rarengine

`rarengine` is a custom, high-speed, zero-allocation, stream-oriented RAR5 decompression engine written from scratch in Go. 

Designed specifically for high-throughput Usenet downloaders (like `gonzbd`), `rarengine` decompresses RAR5 streams on-the-fly directly from network/Go channels and sliding window buffers, achieving maximum CPU efficiency and maintaining a strictly flat memory footprint.

---

## Key Features

- **Zero-Allocation Pipeline**: Reuses single `StreamDecompressor` instances and pre-allocated 32MB sliding windows across streams, slashing memory allocations to **under 2 KB per run**.
- **Automatic Volume Unpacker**: Unpacks directory-based multi-volume archives automatically via `UnpackDir`, discovering and ordering `.partX.rar` files dynamically.
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
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/hobeone/rarengine"
)

func main() {
	// 1. Open your RAR file (or multi-volume channel)
	f, err := os.Open("archive.rar")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	// 2. Initialize the decompressor
	sd := rarengine.NewStreamDecompressor(volumes)
	sd.SetPassword("my-safe-password") // Configure if archive is encrypted (RAR5 only)

	// 3. Process files sequentially
	for {
		fh, err := sd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, rarengine.ErrNoNextVolume) {
				break
			}
			// One member failing does not mean the archive is over. A
			// *FileError names the member and leaves the stream on the next
			// block header, so the files behind it are still reachable.
			var damaged *rarengine.FileError
			if errors.As(err, &damaged) {
				fmt.Printf("Skipping %s: %v\n", damaged.Header.Name, damaged.Err)
				continue
			}
			panic(err)
		}

		if fh.IsDir {
			fmt.Printf("Directory: %s\n", fh.Name)
			continue
		}

		fmt.Printf("Extracting: %s (%d bytes)\n", fh.Name, fh.UnpackedSize)

		// 4. Stream payload directly
		data := make([]byte, fh.UnpackedSize)
		_, err = io.ReadFull(sd, data)
		if err != nil {
			panic(err)
		}

		fmt.Printf("File Content: %q\n", string(data))
	}
}
```

### High-Throughput Reuse (Zero-Allocation Reset)

```go
// Reset the stream decompressor to process a new set of volumes
// reusing the existing 32MB sliding window memory:
sd.Reset(newVolumesChan)
```

### High-Level Directory Decompression (Automatic Volume Discovery & Extraction)

For standard extraction directly to a target directory, `rarengine` provides a robust, sandboxed `UnpackDir` utility. It automatically discovers other volumes (e.g., `.part1.rar`, `.part2.rar`), sorts them by internal headers, sandboxes file generation inside the target directory, and unpacks the contents.

A member that cannot be delivered — it ended short, failed its checksum, tripped the rar-bomb guard, or has a name that is unusable once sanitized — is reported in `UnpackResult.Damaged` rather than aborting the extraction, because in a non-solid archive the members behind it are independently readable. Each member is written under a temporary name and renamed into place only once it has decoded completely, so a damaged member never appears at its destination and `Files` and `Damaged` stay disjoint on disk.

Two cases still end the traversal, each returning the result accumulated so far alongside the error: a solid archive, whose members back-reference their predecessors' decoded bytes and so cannot be resumed past damage (`ErrSolidStreamBroken`), and a member whose header does not parse, which is refused before there is a header to name it with.

Encryption is supported for RAR5 only. An encrypted RAR3 member is refused with `ErrRAR3EncryptionUnsupported` rather than decoded, because this library implements no RAR3 key derivation and so cannot produce the content whatever password is supplied — `SetPassword` and `UnpackOptions.Password` configure RAR5 decryption alone. The refusal names the member, so it is reported in `Damaged` and the rest of the archive stays readable. Two variants end the traversal instead: an archive whose block headers are themselves encrypted, since the headers that would name the remaining members cannot be read, and a member whose *continuation* claims encryption when its first block did not, since the stream is no longer known to be standing on a block header.

```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/hobeone/rarengine"
)

func main() {
	ctx := context.Background()
	firstVolume := "archive.part1.rar"
	outputDir := "./extracted"

	opts := rarengine.UnpackOptions{
		Password:       "my-secret-password",             // If password-encrypted (RAR5 only)
		Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)), // Enable internal trace logging
		OneFolder:      false,                            // Retain internal folder structures
		OverwriteFiles: true,                             // Overwrite existing files in output directory
	}

	res, err := rarengine.UnpackDir(ctx, firstVolume, outputDir, opts)
	if err != nil {
		// Archive-level failure: the volumes could not be opened, or the
		// stream stopped being parseable. res still holds whatever was
		// extracted before that point.
		panic(err)
	}

	fmt.Printf("Successfully extracted %d files:\n", len(res.Files))
	for _, file := range res.Files {
		fmt.Println("-", file)
	}

	// A damaged member no longer costs you the rest of the archive. Nothing
	// was written to disk for these, so Files and Damaged never overlap.
	for _, d := range res.Damaged {
		fmt.Printf("- DAMAGED %s: %v\n", d.Header.Name, d.Err)
	}
}
```

---

## Benchmarks

Benchmarks are run using:
```bash
go test -bench=. -benchmem
```

On an **AMD Ryzen 9 9950X3D** CPU, the decompressor achieves the following performance metrics:

```
BenchmarkDecompress_Store-32       2751678     425.5 ns/op   35.25 MB/s      848 B/op   22 allocs/op
BenchmarkDecompress_Compress-32    1547181     782.9 ns/op   48.54 MB/s     1440 B/op   37 allocs/op
BenchmarkDecompress_Solid-32        274993    4230.0 ns/op    8.98 MB/s     1704 B/op   48 allocs/op
```

*(By reusing the sliding window and `StreamDecompressor` instance via `Reset`, allocations during processing dropped from **33.5 MB** to **under 2 KB** per session, unleashing extreme execution throughput).*

---

## Security

Please report security issues or concerns. Decompression exploits (corrupt payloads, directory traversals, and decompression bombs) are guarded proactively by design.

---

## License

This project is licensed under the MIT License.
