package rarengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadFilter5Data(t *testing.T) {
	// A bitstream encoding:
	// - 2 bits for bytesVal (value - 1) -> let's say bytesVal = 2 (so we write 1: 0x01)
	// - 2 bytes of payload (each 8 bits): 0x34, 0x12 -> represents 0x1234
	// In bits (MSB first, so we read 2 bits first, then 8, then 8):
	// Let's create a BitReader from binary sequence
	// 01 (bytesVal=1, meaning 2 bytes) followed by 0x34 (00110100) and 0x12 (00010010)
	// Output should be: 0x1234 = 4660
	// Let's construct the bits:
	// 01 00110100 00010010 -> 01001101 00000100 10000000 = 0x4D, 0x04, 0x80
	buf := []byte{0x4d, 0x04, 0x80}
	br := NewBitReader(buf, len(buf)*8)

	val, err := readFilter5Data(br)
	if err != nil {
		t.Fatalf("readFilter5Data failed: %v", err)
	}
	expected := int64(0x1234)
	if val != expected {
		t.Errorf("expected %d, got %d", expected, val)
	}

	// Error path: EOF
	brEOF := NewBitReader([]byte{0x00}, 2) // not enough bits
	_, err = readFilter5Data(brEOF)
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestDecoder50_ReadFilter(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(1024)

	// A delta filter at raw offset 0x10, block length 0x08, param 5.
	err := queueOne(d, win, 0x10, 0x08, 0, 5)
	if err != nil {
		t.Fatalf("readFilter failed: %v", err)
	}

	if len(d.fl) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(d.fl))
	}

	fb := d.fl[0]
	if fb.ftype != 0 {
		t.Errorf("expected ftype 0, got %d", fb.ftype)
	}
	if fb.param != 5 {
		t.Errorf("expected param 5, got %d", fb.param)
	}
	// Nothing has been decoded yet, so the start is the raw stream value.
	if fb.start != 0x10 {
		t.Errorf("expected start 0x10, got %#x", fb.start)
	}
	if fb.length != 0x08 {
		t.Errorf("expected length 0x08, got %#x", fb.length)
	}

	// Test ErrTooManyFilters limit
	d.fl = make([]FilterBlock, maxQueuedFilters)
	err = d.readFilter(win)
	if !errors.Is(err, ErrTooManyFilters) {
		t.Errorf("expected ErrTooManyFilters, got %v", err)
	}
}

func TestDecoder50_DecodeSymbol(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(1024)

	// Initialize offset history
	d.offset = [4]int{10, 20, 30, 40}

	// 1. Literal symbol (< 256)
	err := d.decodeSymbol(win, 65)
	if err != nil {
		t.Fatalf("literal decode failed: %v", err)
	}
	if win.Available() != 1 {
		t.Errorf("expected 1 byte in window, got %d", win.Available())
	}
	var out [1]byte
	n, _ := win.Read(out[:])
	if n != 1 || out[0] != 65 {
		t.Errorf("expected 'A' (65), got %d (%v)", out[0], out)
	}

	// 2. Repetition symbol == 257 (repeats last offset/length)
	d.length = 3
	// Write some historical bytes to copy from: "ABC" at offset 0, window pointer win.w is now 1.
	// Let's reset window and write "hello"
	win.Reset(false)
	win.writeByte('h')
	win.writeByte('e')
	win.writeByte('l')
	win.writeByte('l')
	win.writeByte('o')
	// win.w is now 5. win.r is 0.
	// Let's decode symbol 257 to copy 3 bytes from offset d.offset[0] = 10.
	// Wait, window offset 10 from current w(5) is wrap-around. Let's make offset 2.
	d.offset[0] = 2 // will copy from w - 2 = 3 (index 3 is 'l')
	err = d.decodeSymbol(win, 257)
	if err != nil {
		t.Fatalf("symbol 257 decode failed: %v", err)
	}

	// We expect 3 bytes copied from w - 2 = 3.
	// Indices are:
	// 0: h, 1: e, 2: l, 3: l, 4: o
	// Copy 3 bytes starting at index 3: 'l', 'o', 'l' (overlapping/wraparound copy)
	// Let's read out the new window content.
	buf := make([]byte, win.Available())
	_, _ = win.Read(buf)
	expectedStr := "hellolol"
	if string(buf) != expectedStr {
		t.Errorf("expected window content %q, got %q", expectedStr, string(buf))
	}
}

// TestEntry_RejectsOverReachingBackReference exercises the disclosure at the
// public API boundary: a back-reference reaching past the bytes the current
// file has produced used to surface the previous file's plaintext from
// Entry.Read.
//
// The over-reaching distance is injected as an already-decoded offset rather
// than encoded as a Huffman-coded bit stream. Nothing sits between the decoded
// offset and CopyBytes, so how the value was derived does not affect what is
// under test here.
func TestEntry_RejectsOverReachingBackReference(t *testing.T) {
	win := NewWindow(0x40000)
	fillWindowWithPriorFile(win)

	// A new non-solid file begins, exactly as buildChain does.
	win.Reset(false)

	dec := newDecoder50()
	dec.init(bytes.NewReader(nil), true)
	lz := &lz50Reader{dec: dec, win: win}
	e := newEntry(&FileHeader{Name: "current.bin", UnpackedSize: 16, LastBlock: true}, lz)

	// The file's first token is a match reaching 1000 bytes back, before it has
	// produced anything at all.
	dec.offset[0] = 1000
	dec.length = 16
	err := dec.decodeSymbol(win, 257)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Fatalf("over-reaching back-reference accepted: %v", err)
	}

	// Nothing surfaces through the public API. Checking the byte count matters
	// as much as the error: a CRC failure returns data alongside its error, so
	// "an error came back" would not by itself prove the bytes stayed in.
	// (That the window itself stages nothing is covered one layer down, by
	// TestWindow_CopyBytes_DoesNotLeakPriorFile.)
	out := make([]byte, 16)
	n, _ := e.Read(out)
	if n != 0 {
		t.Fatalf("Entry.Read produced %d bytes after a rejected copy: %q", n, out[:n])
	}
	if bytes.Contains(out, []byte("SECRET")) {
		t.Fatalf("prior file's content leaked: %q", out)
	}
}
