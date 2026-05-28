package rarengine

import (
	"errors"
	"io"
	"testing"
)

func TestBitReader_Basic(t *testing.T) {
	// 0b10110011 0b01101101 -> 0xb3, 0x6d
	buf := []byte{0xb3, 0x6d}
	r := NewBitReader(buf, 16)

	// Read 3 bits (should extract 0b101 -> 5)
	val, err := r.ReadBits(3)
	if err != nil {
		t.Fatalf("ReadBits(3) failed: %v", err)
	}
	if val != 5 {
		t.Errorf("expected 5, got %d", val)
	}

	// Read 5 bits (should extract remaining 0b10011 -> 19)
	val, err = r.ReadBits(5)
	if err != nil {
		t.Fatalf("ReadBits(5) failed: %v", err)
	}
	if val != 19 {
		t.Errorf("expected 19, got %d", val)
	}

	// Read 8 bits (should extract 0b01101101 -> 109 / 0x6d)
	val, err = r.ReadBits(8)
	if err != nil {
		t.Fatalf("ReadBits(8) failed: %v", err)
	}
	if val != 109 {
		t.Errorf("expected 109, got %d", val)
	}
}

func TestBitReader_PeekAndAdvance(t *testing.T) {
	buf := []byte{0xf0, 0x00}
	r := NewBitReader(buf, 16)

	// Peek 4 bits (should be 0b1111 -> 15)
	val := r.PeekBits(4)
	if val != 15 {
		t.Errorf("expected 15, got %d", val)
	}

	// Peek 8 bits (should be 0xf0 -> 240)
	val = r.PeekBits(8)
	if val != 240 {
		t.Errorf("expected 240, got %d", val)
	}

	// Advance by 4 bits
	r.Advance(4)

	// Read 4 bits (should be remaining 0)
	val2, err := r.ReadBits(4)
	if err != nil {
		t.Fatalf("ReadBits(4) failed: %v", err)
	}
	if val2 != 0 {
		t.Errorf("expected 0, got %d", val2)
	}
}

func TestBitReader_Limits(t *testing.T) {
	buf := []byte{0xff}
	r := NewBitReader(buf, 4)

	_, err := r.ReadBits(3)
	if err != nil {
		t.Fatal(err)
	}

	// Reading another 2 bits exceeds limit of 4
	_, err = r.ReadBits(2)
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
}
