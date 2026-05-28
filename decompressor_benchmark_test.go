package rarengine_test

import (
	"bytes"
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

	// Preallocate the StreamDecompressor once outside the timing loop
	dummyVol := make(chan io.ReadCloser, 1)
	dummyVol <- io.NopCloser(bytes.NewReader(data))
	close(dummyVol)
	sd := rarengine.NewStreamDecompressor(dummyVol)

	buf := make([]byte, 4096)

	b.ReportAllocs()

	for b.Loop() {
		f := io.NopCloser(bytes.NewReader(data))
		volChan := make(chan io.ReadCloser, 1)
		volChan <- f
		close(volChan)

		sd.Reset(volChan)
		fh, err := sd.Next()
		if err != nil {
			b.Fatal(err)
		}

		for {
			_, err := sd.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				b.Fatal(err)
			}
		}
		b.SetBytes(fh.UnpackedSize)
	}
}

func BenchmarkDecompress_Compress(b *testing.B) {
	archivePath := filepath.Join("testdata", "rar5_compress.rar")
	data, err := os.ReadFile(archivePath)
	if err != nil {
		b.Fatal(err)
	}

	// Preallocate the StreamDecompressor once outside the timing loop
	dummyVol := make(chan io.ReadCloser, 1)
	dummyVol <- io.NopCloser(bytes.NewReader(data))
	close(dummyVol)
	sd := rarengine.NewStreamDecompressor(dummyVol)

	buf := make([]byte, 4096)

	b.ReportAllocs()

	for b.Loop() {
		f := io.NopCloser(bytes.NewReader(data))
		volChan := make(chan io.ReadCloser, 1)
		volChan <- f
		close(volChan)

		sd.Reset(volChan)
		var totalBytes int64
		for {
			_, err := sd.Next()
			if err != nil {
				if err == rarengine.ErrNoNextVolume || err == io.EOF {
					break
				}
				b.Fatal(err)
			}

			for {
				n, err := sd.Read(buf)
				totalBytes += int64(n)
				if err != nil {
					if err == io.EOF {
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

	// Preallocate the StreamDecompressor once outside the timing loop
	dummyVol := make(chan io.ReadCloser, 1)
	dummyVol <- io.NopCloser(bytes.NewReader(data))
	close(dummyVol)
	sd := rarengine.NewStreamDecompressor(dummyVol)

	buf := make([]byte, 4096)

	b.ReportAllocs()

	for b.Loop() {
		f := io.NopCloser(bytes.NewReader(data))
		volChan := make(chan io.ReadCloser, 1)
		volChan <- f
		close(volChan)

		sd.Reset(volChan)
		var totalBytes int64
		for {
			_, err := sd.Next()
			if err != nil {
				if err == rarengine.ErrNoNextVolume || err == io.EOF {
					break
				}
				b.Fatal(err)
			}

			for {
				n, err := sd.Read(buf)
				totalBytes += int64(n)
				if err != nil {
					if err == io.EOF {
						break
					}
					b.Fatal(err)
				}
			}
			b.SetBytes(totalBytes)
		}
	}
}
