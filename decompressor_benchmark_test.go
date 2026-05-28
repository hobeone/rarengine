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

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		f := io.NopCloser(bytes.NewReader(data))
		volumes := make(chan io.ReadCloser, 1)
		volumes <- f
		close(volumes)

		sd := rarengine.NewStreamDecompressor(volumes)
		fh, err := sd.Next()
		if err != nil {
			b.Fatal(err)
		}

		buf := make([]byte, 4096)
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

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		f := io.NopCloser(bytes.NewReader(data))
		volumes := make(chan io.ReadCloser, 1)
		volumes <- f
		close(volumes)

		sd := rarengine.NewStreamDecompressor(volumes)
		var totalBytes int64
		for {
			_, err := sd.Next()
			if err != nil {
				if err == rarengine.ErrNoNextVolume || err == io.EOF {
					break
				}
				b.Fatal(err)
			}

			buf := make([]byte, 4096)
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
	archivePath := filepath.Join("testdata", "rar5_solid.rar")
	data, err := os.ReadFile(archivePath)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		f := io.NopCloser(bytes.NewReader(data))
		volumes := make(chan io.ReadCloser, 1)
		volumes <- f
		close(volumes)

		sd := rarengine.NewStreamDecompressor(volumes)
		var totalBytes int64
		for {
			_, err := sd.Next()
			if err != nil {
				if err == rarengine.ErrNoNextVolume || err == io.EOF {
					break
				}
				b.Fatal(err)
			}

			buf := make([]byte, 4096)
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
