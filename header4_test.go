package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
)

// badCRC returns block with its HEAD_CRC inverted.
func badCRC(block []byte) []byte {
	b := append([]byte{}, block...)
	b[0], b[1] = ^b[0], ^b[1]
	return b
}

// TestReadBlockHeader4_LargeFileIsOneCount pins that a file header's packed
// size is one 64-bit count, PACK_SIZE | HIGH_PACK_SIZE<<32, and that it is
// DataSize -- the number the traversal skips -- that carries it.
func TestReadBlockHeader4_LargeFileIsOneCount(t *testing.T) {
	block := rar4File(rar4FileSpec{
		Name: []byte("big.bin"), Flags: rar4FileLarge | rar4LongBlock,
		PackLow: 0x10, PackHigh: 1, UnpLow: 0x10, UnpHigh: 1, Method: 0x30, UnpVer: 20,
	})
	h, err := readBlockHeader4(bytes.NewReader(block))
	if err != nil {
		t.Fatalf("readBlockHeader4: %v", err)
	}
	if h.DataSize != 1<<32|0x10 {
		t.Errorf("DataSize = %#x, want %#x", h.DataSize, int64(1<<32|0x10))
	}
	if h.Type != headerTypeFile || !h.rar4 {
		t.Errorf("Type = %d, rar4 = %v; want %d, true", h.Type, h.rar4, headerTypeFile)
	}
	if !bytes.Equal(h.Payload, block[7:]) {
		t.Errorf("Payload is not the header bytes after the base")
	}
}

func TestReadBlockHeader4_TypeMapping(t *testing.T) {
	for _, tc := range []struct {
		raw  byte
		want uint64
	}{
		{0x73, headerTypeArchive},
		{0x74, headerTypeFile},
		{0x7a, headerTypeService},
		{0x7b, headerTypeEnd},
		{0x72, 0x172},
		{0x7c, 0x17c},
	} {
		var body []byte
		if tc.raw == 0x74 || tc.raw == 0x7a {
			body = make([]byte, 25)
		}
		h, err := readBlockHeader4(bytes.NewReader(rar4Block(tc.raw, 0, body)))
		if err != nil {
			t.Errorf("type %#x: %v", tc.raw, err)
			continue
		}
		if h.Type != tc.want {
			t.Errorf("type %#x mapped to %#x, want %#x", tc.raw, h.Type, tc.want)
		}
		if tc.want > 0xff && h.Type >= headerTypeArchive && h.Type <= headerTypeEnd {
			t.Errorf("unmapped type %#x landed on a RAR5 type %d", tc.raw, h.Type)
		}
	}
}

func TestReadBlockHeader4_LongBlockAddSize(t *testing.T) {
	addSize := binary.LittleEndian.AppendUint32(nil, 100)
	h, err := readBlockHeader4(bytes.NewReader(rar4Block(0x7b, rar4LongBlock, addSize)))
	if err != nil || h.DataSize != 100 {
		t.Fatalf("with LONG_BLOCK: DataSize = %v, %v; want 100", h, err)
	}
	h, err = readBlockHeader4(bytes.NewReader(rar4Block(0x7b, 0, addSize)))
	if err != nil || h.DataSize != 0 {
		t.Fatalf("without LONG_BLOCK: DataSize = %v, %v; want 0", h, err)
	}
}

func TestReadBlockHeader4_BadCRC(t *testing.T) {
	block := rar4File(rar4FileSpec{Name: []byte("a"), Flags: rar4LongBlock, PackLow: 1, Method: 0x30})
	block[12] ^= 0x01 // a byte inside UNP_SIZE
	if _, err := readBlockHeader4(bytes.NewReader(block)); !errors.Is(err, ErrBadHeaderCRC) {
		t.Fatalf("err = %v, want ErrBadHeaderCRC", err)
	}
}

// TestReadBlockHeader4_ShortHeaders pins that a HEAD_SIZE too small for the
// fields its type requires is corrupt, rather than read past.
func TestReadBlockHeader4_ShortHeaders(t *testing.T) {
	headSize6 := rar4Block(0x7b, 0, nil)
	binary.LittleEndian.PutUint16(headSize6[5:], 6)

	for name, block := range map[string][]byte{
		"HEAD_SIZE 6":             headSize6,
		"file HEAD_SIZE 10":       rar4Block(0x74, 0, make([]byte, 3)),
		"LARGE file HEAD_SIZE 38": rar4Block(0x74, rar4FileLarge, make([]byte, 31)),
		"LARGE file HEAD_SIZE 39": rar4Block(0x74, rar4FileLarge, make([]byte, 32)),
	} {
		if _, err := readBlockHeader4(bytes.NewReader(block)); !errors.Is(err, ErrCorruptBlockHeader) {
			t.Errorf("%s: err = %v, want ErrCorruptBlockHeader", name, err)
		}
	}
}

// TestReadBlockHeader4_LegacyBlocksRefusedByName pins that the RAR 2.x block
// types are named as unsupported before their CRC is looked at: unrar does not
// check some of them, so a CRC mismatch there would misreport a valid old
// archive as damaged.
func TestReadBlockHeader4_LegacyBlocksRefusedByName(t *testing.T) {
	for typ := byte(0x75); typ <= 0x79; typ++ {
		_, err := readBlockHeader4(bytes.NewReader(badCRC(rar4Block(typ, 0, make([]byte, 8)))))
		if !errors.Is(err, ErrUnsupportedFormat) || errors.Is(err, ErrBadHeaderCRC) {
			t.Errorf("type %#x: err = %v, want ErrUnsupportedFormat", typ, err)
		}
	}
}

// TestReadBlockHeader4_EmbeddedCommentRefusedByName is the same for a RAR 2.x
// comment carried inside a main or file header, whose CRC covers only part of
// the header.
func TestReadBlockHeader4_EmbeddedCommentRefusedByName(t *testing.T) {
	for name, block := range map[string][]byte{
		"main": rar4Block(0x73, rar4MainComment, make([]byte, 6)),
		"file": rar4File(rar4FileSpec{Name: []byte("a"), Flags: rar4LongBlock | rar4FileComment}),
	} {
		_, err := readBlockHeader4(bytes.NewReader(badCRC(block)))
		if !errors.Is(err, ErrUnsupportedFormat) || errors.Is(err, ErrBadHeaderCRC) {
			t.Errorf("%s: err = %v, want ErrUnsupportedFormat", name, err)
		}
	}
}

// TestReadBlockHeader4_CutHeaderIsUnexpectedEOF pins that a volume ending
// inside a header is truncation at every offset, and only ending before its
// first byte is the clean io.EOF of a block boundary.
func TestReadBlockHeader4_CutHeaderIsUnexpectedEOF(t *testing.T) {
	block := rar4File(rar4FileSpec{Name: []byte("cut.bin"), Flags: rar4LongBlock, PackLow: 4, Method: 0x30})
	if _, err := readBlockHeader4(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("empty: err = %v, want io.EOF", err)
	}
	for k := 1; k < len(block); k++ {
		if _, err := readBlockHeader4(bytes.NewReader(block[:k])); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("cut %d bytes into a %d-byte header: err = %v, want io.ErrUnexpectedEOF", k, len(block), err)
		}
	}
}

// TestReadBlockHeader4_RealFixture walks a rar-written archive with a
// recovery record. The RR block's 514 bytes were read off the fixture
// independently of this code.
func TestReadBlockHeader4_RealFixture(t *testing.T) {
	arc, err := os.ReadFile("testdata/rar4_rr.rar")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(arc[len(rar4Sig):])
	var types []uint64
	var sizes []int64
	for {
		h, err := readBlockHeader4(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("after %v: %v", types, err)
		}
		types = append(types, h.Type)
		sizes = append(sizes, h.DataSize)
		if _, err := r.Seek(h.DataSize, io.SeekCurrent); err != nil {
			t.Fatal(err)
		}
	}
	wantTypes := []uint64{headerTypeArchive, headerTypeFile, headerTypeService, headerTypeEnd}
	wantSizes := []int64{0, 15, 514, 0}
	if !slices.Equal(types, wantTypes) || !slices.Equal(sizes, wantSizes) {
		t.Fatalf("types %v sizes %v; want %v %v", types, sizes, wantTypes, wantSizes)
	}
}
