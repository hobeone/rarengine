package rarengine_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hobeone/rarengine"
)

// latentReader simulates a source where each Read incurs a fixed latency
// (e.g., a network syscall round-trip). The decoder issues a mix of small
// header reads and large payload reads; under per-Read latency the small
// reads dominate, which is exactly the regime where BufferedVolume's
// chunked read-ahead pays off.
type latentReader struct {
	data    []byte
	off     int
	latency time.Duration
}

func (l *latentReader) Read(p []byte) (int, error) {
	if l.off >= len(l.data) {
		return 0, io.EOF
	}
	time.Sleep(l.latency)
	n := copy(p, l.data[l.off:])
	l.off += n
	return n, nil
}

func (l *latentReader) Close() error { return nil }

func loadSolidFixture(b *testing.B) []byte {
	b.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rar5_solid_bench.rar"))
	if err != nil {
		b.Fatal(err)
	}
	return data
}

// BenchmarkDecompress_Solid_LatentDirect feeds the decompressor a latency-
// limited source without any buffering. Establishes the worst case where
// every Read call blocks on simulated I/O.
func BenchmarkDecompress_Solid_LatentDirect(b *testing.B) {
	data := loadSolidFixture(b)
	const latency = 200 * time.Microsecond
	sd := rarengine.NewStreamDecompressor(nil)
	buf := make([]byte, 32<<10)

	b.ReportAllocs()
	for b.Loop() {
		volChan := make(chan io.ReadCloser, 1)
		volChan <- &latentReader{data: data, latency: latency}
		close(volChan)
		sd.Reset(volChan)

		var n int64
		for {
			if _, err := sd.Next(); err != nil {
				if err == io.EOF || err == rarengine.ErrNoNextVolume {
					break
				}
				b.Fatal(err)
			}
			for {
				m, err := sd.Read(buf)
				n += int64(m)
				if err != nil {
					if err == io.EOF {
						break
					}
					b.Fatal(err)
				}
			}
		}
		b.SetBytes(n)
	}
}

// BenchmarkDecompress_Solid_LatentBuffered wraps the same latency-limited
// source in BufferedVolume so the decompressor's reads are served from a
// background-pumped buffer. Demonstrates Strategy B: I/O overlaps with CPU.
func BenchmarkDecompress_Solid_LatentBuffered(b *testing.B) {
	data := loadSolidFixture(b)
	const latency = 200 * time.Microsecond
	sd := rarengine.NewStreamDecompressor(nil)
	buf := make([]byte, 32<<10)

	b.ReportAllocs()
	for b.Loop() {
		volChan := make(chan io.ReadCloser, 1)
		src := &latentReader{data: data, latency: latency}
		volChan <- rarengine.BufferedVolume(src, 4<<20)
		close(volChan)
		sd.Reset(volChan)

		var n int64
		for {
			if _, err := sd.Next(); err != nil {
				if err == io.EOF || err == rarengine.ErrNoNextVolume {
					break
				}
				b.Fatal(err)
			}
			for {
				m, err := sd.Read(buf)
				n += int64(m)
				if err != nil {
					if err == io.EOF {
						break
					}
					b.Fatal(err)
				}
			}
		}
		b.SetBytes(n)
	}
}

// BenchmarkDecompress_Solid_FastBuffered confirms BufferedVolume adds no
// regression on a zero-latency source (the case where Strategy B has nothing
// to overlap). Acts as a sanity check that the wrapper isn't a net pessimism
// when the source is already fast.
func BenchmarkDecompress_Solid_FastBuffered(b *testing.B) {
	data := loadSolidFixture(b)
	sd := rarengine.NewStreamDecompressor(nil)
	buf := make([]byte, 32<<10)

	b.ReportAllocs()
	for b.Loop() {
		volChan := make(chan io.ReadCloser, 1)
		volChan <- rarengine.BufferedVolume(io.NopCloser(bytes.NewReader(data)), 4<<20)
		close(volChan)
		sd.Reset(volChan)

		var n int64
		for {
			if _, err := sd.Next(); err != nil {
				if err == io.EOF || err == rarengine.ErrNoNextVolume {
					break
				}
				b.Fatal(err)
			}
			for {
				m, err := sd.Read(buf)
				n += int64(m)
				if err != nil {
					if err == io.EOF {
						break
					}
					b.Fatal(err)
				}
			}
		}
		b.SetBytes(n)
	}
}
