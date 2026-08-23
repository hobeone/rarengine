package rarengine

import (
	"errors"
	"testing"
)

// A RAR5 vint carries 70 bits, so every length an archive declares can be
// given a value whose int conversion is negative. A negative length passes
// "is this longer than what I hold?" and then panics the process at the
// slice bound it was supposed to guard -- a crafted header killing the
// caller, not merely failing to parse.
//
// Mutation check: restore the int casts these pin (int(nameLen),
// int(exSizeV), int(exRecSizeV)) and each of these tests panics with
// "slice bounds out of range" instead of failing.

const signBitVint = uint64(1) << 63

func TestFileHeaderRejectsNameLenSignWrap(t *testing.T) {
	var p []byte
	p = append(p, EncodeVint(0)...)           // flags
	p = append(p, EncodeVint(1)...)           // unpacked size
	p = append(p, EncodeVint(0)...)           // attributes
	p = append(p, EncodeVint(0)...)           // compression flags
	p = append(p, EncodeVint(0)...)           // host OS
	p = append(p, EncodeVint(signBitVint)...) // name length

	fh, err := parseFileHeader(&BlockHeader{Type: HeaderTypeFile, Payload: p})
	if !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("parseFileHeader = (%v, %v), want ErrCorruptFileHeader", fh, err)
	}
}

func TestBlockHeaderRejectsExtraSizeSignWrap(t *testing.T) {
	buf := EncodeVint(99) // header size vint, the n bytes the parser skips
	n := len(buf)
	buf = append(buf, EncodeVint(uint64(HeaderTypeFile))...)
	buf = append(buf, EncodeVint(uint64(HeaderFlagHasExtra))...)
	buf = append(buf, EncodeVint(signBitVint)...)

	h, err := parseBlockHeaderFields(buf, n)
	if !errors.Is(err, ErrCorruptBlockHeader) {
		t.Fatalf("parseBlockHeaderFields = (%v, %v), want ErrCorruptBlockHeader", h, err)
	}
}

func TestBlockHeaderRejectsExtraRecordSizeSignWrap(t *testing.T) {
	// One extra record whose declared size wraps negative. extraSize itself
	// is honest, so the block-level bound above passes and the per-record
	// bound is the one under test.
	rec := EncodeVint(signBitVint)

	buf := EncodeVint(99)
	n := len(buf)
	buf = append(buf, EncodeVint(uint64(HeaderTypeFile))...)
	buf = append(buf, EncodeVint(uint64(HeaderFlagHasExtra))...)
	buf = append(buf, EncodeVint(uint64(len(rec)))...)
	buf = append(buf, rec...)

	h, err := parseBlockHeaderFields(buf, n)
	if !errors.Is(err, ErrCorruptBlockHeader) {
		t.Fatalf("parseBlockHeaderFields = (%v, %v), want ErrCorruptBlockHeader", h, err)
	}
}
