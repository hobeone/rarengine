package rarengine_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hobeone/rarengine"
)

func BenchmarkDecompress_Store(b *testing.B) {
	archivePath := filepath.Join("testdata", "rar5_store.rar")
	data, err := os.ReadFile(archivePath)
	if err != nil {
		b.Fatal(err)
	}

	// Preallocate the Reader once outside the timing loop, so Reset's window
	// reuse is what the loop measures rather than allocation of a fresh one.
	dummyVol := make(chan io.ReadCloser, 1)
	dummyVol <- io.NopCloser(bytes.NewReader(data))
	close(dummyVol)
	r := rarengine.NewReader(dummyVol)

	buf := make([]byte, 4096)

	b.ReportAllocs()

	for b.Loop() {
		f := io.NopCloser(bytes.NewReader(data))
		volChan := make(chan io.ReadCloser, 1)
		volChan <- f
		close(volChan)

		r.Reset(volChan)
		e, err := r.NextEntry()
		if err != nil {
			b.Fatal(err)
		}

		for {
			_, err := e.Read(buf)
			if err != nil {
				if err == io.EOF { //nolint:errorlint // sentinel comparison, matches original benchmark
					break
				}
				b.Fatal(err)
			}
		}
		b.SetBytes(e.Header.UnpackedSize)
	}
}

func BenchmarkDecompress_Compress(b *testing.B) {
	archivePath := filepath.Join("testdata", "rar5_compress.rar")
	data, err := os.ReadFile(archivePath)
	if err != nil {
		b.Fatal(err)
	}

	dummyVol := make(chan io.ReadCloser, 1)
	dummyVol <- io.NopCloser(bytes.NewReader(data))
	close(dummyVol)
	r := rarengine.NewReader(dummyVol)

	buf := make([]byte, 4096)

	b.ReportAllocs()

	for b.Loop() {
		f := io.NopCloser(bytes.NewReader(data))
		volChan := make(chan io.ReadCloser, 1)
		volChan <- f
		close(volChan)

		r.Reset(volChan)
		var totalBytes int64
		for {
			e, err := r.NextEntry()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				b.Fatal(err)
			}

			for {
				n, err := e.Read(buf)
				totalBytes += int64(n)
				if err != nil {
					if err == io.EOF { //nolint:errorlint // sentinel comparison, matches original benchmark
						break
					}
					b.Fatal(err)
				}
			}
			b.SetBytes(totalBytes)
		}
	}
}

func BenchmarkDecompress_Solid(b *testing.B) {
	archivePath := filepath.Join("testdata", "rar5_solid_bench.rar")
	data, err := os.ReadFile(archivePath)
	if err != nil {
		b.Fatal(err)
	}

	dummyVol := make(chan io.ReadCloser, 1)
	dummyVol <- io.NopCloser(bytes.NewReader(data))
	close(dummyVol)
	r := rarengine.NewReader(dummyVol)

	buf := make([]byte, 4096)

	b.ReportAllocs()

	for b.Loop() {
		f := io.NopCloser(bytes.NewReader(data))
		volChan := make(chan io.ReadCloser, 1)
		volChan <- f
		close(volChan)

		r.Reset(volChan)
		var totalBytes int64
		for {
			e, err := r.NextEntry()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				b.Fatal(err)
			}

			for {
				n, err := e.Read(buf)
				totalBytes += int64(n)
				if err != nil {
					if err == io.EOF { //nolint:errorlint // sentinel comparison, matches original benchmark
						break
					}
					b.Fatal(err)
				}
			}
			b.SetBytes(totalBytes)
		}
	}
}

// storedArchive loads a small store-method fixture for
// BenchmarkReaderResetReusesWindow, which cares about allocation behaviour
// on Reset rather than about decode throughput -- any small archive does.
func storedArchive(b *testing.B) []byte {
	b.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rar5_store.rar"))
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func volumesOf(data []byte) <-chan io.ReadCloser {
	ch := make(chan io.ReadCloser, 1)
	ch <- io.NopCloser(bytes.NewReader(data))
	close(ch)
	return ch
}

// BenchmarkReaderResetReusesWindow pins the zero-allocation invariant CLAUDE.md
// requires: Reset must reuse the 32 MB window rather than allocating a new
// one. Allocations per op in the low thousands of bytes confirm reuse; tens
// of megabytes would mean Reset allocated a fresh window.
func BenchmarkReaderResetReusesWindow(b *testing.B) {
	stream := storedArchive(b)
	r := rarengine.NewReader(volumesOf(stream))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r.Reset(volumesOf(stream))
		for {
			e, err := r.NextEntry()
			if err != nil {
				break
			}
			_, _ = io.Copy(io.Discard, e)
			_ = e.Close()
		}
	}
}
