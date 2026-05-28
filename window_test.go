package rarengine

import (
	"bytes"
	"errors"
	"testing"
)

func TestWindow_WriteAndRead(t *testing.T) {
	w := NewWindow(256 * 1024) // 256KB
	w.Reset(false)

	// Write 4 bytes
	w.writeByte('A')
	w.writeByte('B')
	w.writeByte('C')
	w.writeByte('D')

	if w.Available() != 4 {
		t.Errorf("expected 4 available bytes, got %d", w.Available())
	}

	out := make([]byte, 4)
	n, err := w.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 4 || !bytes.Equal(out, []byte("ABCD")) {
		t.Errorf("expected ABCD, got %s (n=%d)", out, n)
	}
	if w.Available() != 0 {
		t.Errorf("expected 0 available bytes, got %d", w.Available())
	}
}

func TestWindow_CopyBytes_Overlapping(t *testing.T) {
	w := NewWindow(256 * 1024)
	w.Reset(false)

	// Write 'X'
	w.writeByte('X')

	// Copy 5 bytes from distance 1 (should repeat 'X' 5 times)
	err := w.CopyBytes(5, 1)
	if err != nil {
		t.Fatalf("CopyBytes failed: %v", err)
	}

	if w.Available() != 6 {
		t.Errorf("expected 6 available bytes, got %d", w.Available())
	}

	out := make([]byte, 6)
	_, _ = w.Read(out)
	if !bytes.Equal(out, []byte("XXXXXX")) {
		t.Errorf("expected XXXXXX, got %s", out)
	}
}

func TestWindow_CopyBytes_InvalidOffset(t *testing.T) {
	w := NewWindow(256 * 1024)
	w.Reset(false)

	// Copy from distance 0 (invalid)
	err := w.CopyBytes(5, 0)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Errorf("expected ErrWindowOffsetBounds, got %v", err)
	}

	// Copy from distance larger than window size (invalid)
	err = w.CopyBytes(5, w.size+1)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Errorf("expected ErrWindowOffsetBounds, got %v", err)
	}
}

func TestWindow_Wraparound(t *testing.T) {
	// Let's force a small window size (which falls back to minWindowSize = 256KB = 262144 bytes)
	w := NewWindow(10)
	w.Reset(false)

	// Write 262140 bytes
	for range 262140 {
		w.writeByte('A')
	}

	// Read them all to clear read buffer
	drain := make([]byte, 4096)
	for w.Available() > 0 {
		_, _ = w.Read(drain)
	}

	// Write 10 bytes (this will trigger wraparound at 262144)
	// indices: 262140, 262141, 262142, 262143 (index 0, 1, 2, 3, 4, 5)
	for i := range 10 {
		w.writeByte(byte('0' + i))
	}

	if w.Available() != 10 {
		t.Errorf("expected 10 available bytes, got %d", w.Available())
	}

	out := make([]byte, 10)
	n, err := w.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 10 || !bytes.Equal(out, []byte("0123456789")) {
		t.Errorf("expected 0123456789, got %s (n=%d)", out, n)
	}
}

func TestWindow_CompletelyFull(t *testing.T) {
	w := NewWindow(10)
	w.Reset(false)
	size := w.size

	for i := range size {
		w.writeByte(byte(i % 256))
	}

	if !w.full {
		t.Errorf("expected window to be full")
	}
	if w.Available() != size {
		t.Errorf("expected %d available bytes, got %d", size, w.Available())
	}

	out := make([]byte, size)
	n, err := w.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != size {
		t.Errorf("expected read of %d bytes, got %d", size, n)
	}
	if w.full {
		t.Errorf("expected window to be no longer full after read")
	}
	if w.Available() != 0 {
		t.Errorf("expected 0 available bytes, got %d", w.Available())
	}

	for i := range size {
		if out[i] != byte(i%256) {
			t.Errorf("data mismatch at index %d: expected %d, got %d", i, byte(i%256), out[i])
			break
		}
	}
}
