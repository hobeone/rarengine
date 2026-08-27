package rarengine

import (
	"bytes"
	"errors"
	"testing"
)

func TestVintRoundTrip(t *testing.T) {
	testCases := []uint64{
		0, 1, 127, 128, 255, 300, 16383, 16384,
		0xffffffff, 0x1234567890abcdef, 0xffffffffffffffff,
	}

	for _, tc := range testCases {
		encoded := encodeVint(tc)
		decoded, n, err := decodeVint(encoded)
		if err != nil {
			t.Errorf("DecodeVint(%d) failed: %v", tc, err)
			continue
		}
		if n != len(encoded) {
			t.Errorf("DecodeVint(%d) consumed %d bytes, expected %d", tc, n, len(encoded))
		}
		if decoded != tc {
			t.Errorf("DecodeVint(%d) returned %d, expected %d", tc, decoded, tc)
		}
	}
}

func TestDecodeVintTruncated(t *testing.T) {
	// 1. Empty buffer
	_, _, err := decodeVint(nil)
	if !errors.Is(err, ErrTruncatedVint) {
		t.Errorf("expected ErrTruncatedVint for empty buffer, got %v", err)
	}

	// 2. Incomplete sequence
	buf := []byte{0x80, 0x80, 0x80}
	_, _, err = decodeVint(buf)
	if !errors.Is(err, ErrTruncatedVint) {
		t.Errorf("expected ErrTruncatedVint for incomplete sequence, got %v", err)
	}
}

func TestDecodeVintOversized(t *testing.T) {
	// 11 bytes of 0x80 (exceeds max length of 10)
	buf := bytes.Repeat([]byte{0x80}, 11)
	_, _, err := decodeVint(buf)
	if !errors.Is(err, ErrTruncatedVint) {
		t.Errorf("expected ErrTruncatedVint for 11-byte sequence, got %v", err)
	}
}

func TestDecodeVint_Padding(t *testing.T) {
	// Pre-allocated VINT encoding representation for value 5
	// First byte 0x85 (LSB 5, continuation flag set)
	// Second byte 0x80 (continuation flag set, value 0)
	// Third byte 0x00 (no continuation flag set, value 0)
	buf := []byte{0x85, 0x80, 0x00}
	val, n, err := decodeVint(buf)
	if err != nil {
		t.Fatalf("DecodeVint failed for padded VINT: %v", err)
	}
	if val != 5 {
		t.Errorf("expected decoded value 5, got %d", val)
	}
	if n != 3 {
		t.Errorf("expected consumed bytes 3, got %d", n)
	}
}
