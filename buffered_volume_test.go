package rarengine_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/hobeone/rarengine"
)

type readCloser struct {
	io.Reader
	closed bool
}

func (rc *readCloser) Close() error {
	rc.closed = true
	return nil
}

// erroringReader returns up to `goodBytes` of payload then a sticky error.
type erroringReader struct {
	payload []byte
	off     int
	err     error
}

func (e *erroringReader) Read(p []byte) (int, error) {
	if e.off >= len(e.payload) {
		return 0, e.err
	}
	n := copy(p, e.payload[e.off:])
	e.off += n
	return n, nil
}

func (e *erroringReader) Close() error { return nil }

func TestBufferedVolume_ReadsMatchSource(t *testing.T) {
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	src := &readCloser{Reader: bytes.NewReader(payload)}
	bv := rarengine.BufferedVolume(src, 256<<10)
	defer bv.Close()

	got, err := io.ReadAll(bv)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestBufferedVolume_SmallReadsAcrossChunks(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog 0123456789ABCDEF")
	src := &readCloser{Reader: bytes.NewReader(payload)}
	bv := rarengine.BufferedVolume(src, 64<<10)
	defer bv.Close()

	out := make([]byte, 0, len(payload))
	buf := make([]byte, 3)
	for {
		n, err := bv.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("got %q, want %q", out, payload)
	}
}

func TestBufferedVolume_ErrorPropagation(t *testing.T) {
	want := errors.New("upstream read failure")
	src := &erroringReader{payload: []byte("partial data"), err: want}
	bv := rarengine.BufferedVolume(src, 64<<10)
	defer bv.Close()

	out, err := io.ReadAll(bv)
	if !errors.Is(err, want) {
		t.Fatalf("ReadAll err = %v, want %v", err, want)
	}
	if !bytes.Equal(out, []byte("partial data")) {
		t.Fatalf("got %q, want %q before error", out, "partial data")
	}
}

func TestBufferedVolume_CloseStopsProducer(t *testing.T) {
	before := runtime.NumGoroutine()

	for range 32 {
		// Slow source so the pump is mid-Read when we Close.
		src := &readCloser{Reader: &slowReader{
			data:    bytes.Repeat([]byte("x"), 1<<20),
			perRead: 200 * time.Microsecond,
		}}
		bv := rarengine.BufferedVolume(src, 256<<10)
		buf := make([]byte, 4096)
		_, _ = bv.Read(buf)
		if err := bv.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !src.closed {
			t.Fatal("source not closed after Close")
		}
	}

	// Give scheduler a chance to retire pump goroutines.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Errorf("goroutine leak: started with %d, ended with %d", before, got)
	}
}

func TestBufferedVolume_CloseIdempotent(t *testing.T) {
	src := &readCloser{Reader: bytes.NewReader([]byte("hello"))}
	bv := rarengine.BufferedVolume(src, 64<<10)

	if err := bv.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := bv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// slowReader delivers data with a delay per Read, simulating a slow upstream.
type slowReader struct {
	data    []byte
	off     int
	perRead time.Duration
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.off >= len(s.data) {
		return 0, io.EOF
	}
	time.Sleep(s.perRead)
	n := copy(p, s.data[s.off:])
	s.off += n
	return n, nil
}
