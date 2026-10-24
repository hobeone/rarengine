package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"slices"
	"testing"
	"time"
	"unicode/utf8"
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
	for _, feed := range volumeEnds {
		for k := 1; k < len(block); k++ {
			if _, err := readBlockHeader4(feed.open(block[:k])); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("%s: cut %d bytes into a %d-byte header: err = %v, want io.ErrUnexpectedEOF",
					feed.name, k, len(block), err)
			}
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

// fileHeader4 frames s and reads it back, as the traversal would hand it to
// parseFileHeader4.
func fileHeader4(t *testing.T, s rar4FileSpec) *blockHeader {
	t.Helper()
	h, err := readBlockHeader4(bytes.NewReader(rar4File(s)))
	if err != nil {
		t.Fatalf("readBlockHeader4: %v", err)
	}
	return h
}

// storedSpec is an ordinary stored member header, the base the table tests
// vary one field of.
func storedSpec(name string) rar4FileSpec {
	return rar4FileSpec{
		Name: []byte(name), Flags: rar4LongBlock | 0x20, PackLow: 4, UnpLow: 4,
		HostOS: 3, UnpVer: 20, Method: 0x30, Attr: 0x81a4,
	}
}

func TestParseArchiveHeader4(t *testing.T) {
	for _, tc := range []struct {
		flags     uint16
		multi, so bool
	}{{0, false, false}, {rar4MainVolume | rar4MainSolid, true, true}} {
		h, err := readBlockHeader4(bytes.NewReader(rar4MainHeader(tc.flags)))
		if err != nil {
			t.Fatal(err)
		}
		ah, err := parseArchiveHeader(h)
		if err != nil {
			t.Fatalf("flags %#x: %v", tc.flags, err)
		}
		if ah.MultiVolume != tc.multi || ah.Solid != tc.so || ah.VolumeNumber != -1 {
			t.Errorf("flags %#x: %+v, want MultiVolume %v Solid %v VolumeNumber -1", tc.flags, ah, tc.multi, tc.so)
		}
	}
	h, err := readBlockHeader4(bytes.NewReader(rar4MainHeader(rar4MainPassword)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseArchiveHeader(h); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("encrypted headers: err = %v, want ErrUnsupportedFormat", err)
	}
}

// firstFileHeader4 returns the first file block of a RAR4 fixture.
func firstFileHeader4(t *testing.T, name string) *blockHeader {
	t.Helper()
	arc, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(arc[len(rar4Sig):])
	for {
		h, err := readBlockHeader4(r)
		if err != nil {
			t.Fatalf("%s: no file block: %v", name, err)
		}
		if h.Type == headerTypeFile {
			return h
		}
		if _, err := r.Seek(h.DataSize, io.SeekCurrent); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseFileHeader4_StoredFixture(t *testing.T) {
	h := firstFileHeader4(t, "rar4_store.rar")
	fh, err := parseFileHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if fh.Name != "hello.txt" || fh.Method != 0 || fh.UnpackVersion != 20 || fh.DictSize != 0 {
		t.Errorf("Name %q Method %d UnpackVersion %d DictSize %d; want hello.txt 0 20 0",
			fh.Name, fh.Method, fh.UnpackVersion, fh.DictSize)
	}
	if fh.PackedSize != h.DataSize || fh.PackedSize != 15 || fh.UnpackedSize != 15 {
		t.Errorf("PackedSize %d DataSize %d UnpackedSize %d; want 15 each", fh.PackedSize, h.DataSize, fh.UnpackedSize)
	}
	if !fh.HasCRC32 || fh.CRC32 != crc32.ChecksumIEEE([]byte("hello rardecode")) {
		t.Errorf("HasCRC32 %v CRC32 %#x", fh.HasCRC32, fh.CRC32)
	}
	if !fh.FirstBlock || !fh.LastBlock || fh.HostOS != 1 || fh.IsDir || fh.Encrypted || fh.Solid {
		t.Errorf("FirstBlock %v LastBlock %v HostOS %d IsDir %v Encrypted %v Solid %v",
			fh.FirstBlock, fh.LastBlock, fh.HostOS, fh.IsDir, fh.Encrypted, fh.Solid)
	}
	if fh.Attributes != 0x81b4 || fh.Mode().Perm() != 0o664 {
		t.Errorf("Attributes %#x Mode %v", fh.Attributes, fh.Mode())
	}
}

func TestParseFileHeader4_SplitFlags(t *testing.T) {
	s := storedSpec("a")
	s.Flags |= rar4FileSplitBefore
	if fh, _ := parseFileHeader(fileHeader4(t, s)); fh.FirstBlock || !fh.LastBlock {
		t.Errorf("SPLIT_BEFORE: FirstBlock %v LastBlock %v", fh.FirstBlock, fh.LastBlock)
	}
	s = storedSpec("a")
	s.Flags |= rar4FileSplitAfter
	if fh, _ := parseFileHeader(fileHeader4(t, s)); !fh.FirstBlock || fh.LastBlock {
		t.Errorf("SPLIT_AFTER: FirstBlock %v LastBlock %v", fh.FirstBlock, fh.LastBlock)
	}
}

// TestParseFileHeader4_EncryptedIsThePasswordBit pins that encryption is read
// from LHD_PASSWORD alone. LHD_SALT says a salt follows the name; it does not
// make the member encrypted.
func TestParseFileHeader4_EncryptedIsThePasswordBit(t *testing.T) {
	s := storedSpec("a")
	s.Flags |= rar4FileSalt
	s.Tail = make([]byte, 8)
	if fh, err := parseFileHeader(fileHeader4(t, s)); err != nil || fh.Encrypted {
		t.Errorf("SALT alone: Encrypted %v, %v; want false", fh.Encrypted, err)
	}
	s = storedSpec("a")
	s.Flags |= rar4FilePassword
	if fh, err := parseFileHeader(fileHeader4(t, s)); err != nil || !fh.Encrypted {
		t.Errorf("PASSWORD alone: Encrypted %v, %v; want true", fh.Encrypted, err)
	}
}

// TestParseFileHeader4_StrictMethod pins that only 0x30..0x35 are methods; any
// other byte is a corrupt header, never read as store.
func TestParseFileHeader4_StrictMethod(t *testing.T) {
	for b := byte(0x30); b <= 0x35; b++ {
		s := storedSpec("a")
		s.Method = b
		fh, err := parseFileHeader(fileHeader4(t, s))
		if err != nil || fh.Method != int(b-0x30) {
			t.Errorf("method byte %#x: Method %d, %v; want %d", b, fh.Method, err, b-0x30)
		}
	}
	for _, b := range []byte{0x2f, 0x36, 0x00} {
		s := storedSpec("m")
		s.Method = b
		fh, err := parseFileHeader(fileHeader4(t, s))
		if fh == nil || fh.Name != "m" || !errors.Is(err, ErrCorruptFileHeader) {
			t.Errorf("method byte %#x: fh %v, err %v; want the named header and ErrCorruptFileHeader", b, fh, err)
		}
	}
}

func TestParseFileHeader4_UnknownSize(t *testing.T) {
	s := storedSpec("u")
	s.UnpLow = 0xffffffff
	if fh, err := parseFileHeader(fileHeader4(t, s)); fh == nil || !errors.Is(err, ErrUnpSizeUnknown) {
		t.Errorf("without LARGE: fh %v, err %v; want ErrUnpSizeUnknown with the header", fh, err)
	}
	s.Flags |= rar4FileLarge
	s.UnpHigh = 0xffffffff
	if fh, err := parseFileHeader(fileHeader4(t, s)); fh == nil || !errors.Is(err, ErrUnpSizeUnknown) {
		t.Errorf("with LARGE: fh %v, err %v; want ErrUnpSizeUnknown with the header", fh, err)
	}
	s.UnpHigh = 0 // LARGE with a low half of all ones is an ordinary 4 GiB - 1
	if fh, err := parseFileHeader(fileHeader4(t, s)); err != nil || fh.UnpackedSize != 0xffffffff {
		t.Errorf("LARGE, high 0: UnpackedSize %v, %v; want 0xffffffff", fh, err)
	}
}

func TestParseFileHeader4_NegativeSize(t *testing.T) {
	s := storedSpec("n")
	s.Flags |= rar4FileLarge
	s.UnpHigh = 0x80000000
	if fh, err := parseFileHeader(fileHeader4(t, s)); fh == nil || !errors.Is(err, ErrCorruptFileHeader) {
		t.Errorf("fh %v, err %v; want ErrCorruptFileHeader with the header", fh, err)
	}
}

func TestParseFileHeader4_Directory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		window uint16
		ver    byte
		attr   uint32
		want   bool
	}{
		{"window bits all set", rar4FileDirectory, 20, 0x41fd, true},
		{"RAR 1.5 attribute", 0, 15, 0x10, true},
		{"attribute ignored from 2.0", 0x20, 20, 0x10, false},
	} {
		s := storedSpec("d")
		s.Flags = rar4LongBlock | tc.window
		s.UnpVer, s.Attr = tc.ver, tc.attr
		if fh, err := parseFileHeader(fileHeader4(t, s)); err != nil || fh.IsDir != tc.want {
			t.Errorf("%s: IsDir %v, %v; want %v", tc.name, fh.IsDir, err, tc.want)
		}
	}
}

func TestHostOS4(t *testing.T) {
	for _, b := range []byte{0, 1, 2, 4, 6, 255} {
		if got := hostOS4(b); got != 0 {
			t.Errorf("hostOS4(%d) = %d, want 0", b, got)
		}
	}
	for _, b := range []byte{3, 5} {
		if got := hostOS4(b); got != 1 {
			t.Errorf("hostOS4(%d) = %d, want 1", b, got)
		}
	}
}

func TestParseFileHeader4_UnicodeFixture(t *testing.T) {
	fh, err := parseFileHeader(firstFileHeader4(t, "rar4_unicode.rar"))
	if err != nil || fh.Name != "名前.txt" {
		t.Fatalf("Name %q, %v; want 名前.txt", fh.Name, err)
	}
}

func TestDecodeName4(t *testing.T) {
	// The fixture's own bytes: a UTF-8 rendering, NUL, then HighByte 0x54
	// and the runs 1 (0x540d), 2 (0x524d), 0, 0, a fresh flags byte, 0, 0.
	fixture := []byte("名前.txt\x00\x54\x60\x0d\x4d\x52\x2e\x74\x00\x78\x74")
	// Hand-built over every run kind: HighByte 0x04, flags 0b11_11_00_01 --
	// a copy run of 2 from the ASCII part, a corrected run of 2 ('c'+1,
	// 'd'+1 under HighByte), one literal byte, one byte under HighByte.
	built := []byte("abcdef\x00\x04\xf1\x00\x80\x01\x41\x30")
	for _, tc := range []struct {
		name  string
		flags uint16
		raw   []byte
		want  string
	}{
		{"fixture", rar4FileUnicode, fixture, "名前.txt"},
		{"every run kind", rar4FileUnicode, built, "abѤѥAа"},
		{"unicode flag, no NUL: UTF-8", rar4FileUnicode, []byte("名前.txt"), "名前.txt"},
		{"unicode flag, nothing after NUL", rar4FileUnicode, []byte("plain\x00"), "plain"},
		{"no unicode flag", 0, []byte("plain.txt"), "plain.txt"},
	} {
		if got := decodeName4(tc.flags, tc.raw); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestDecodeName4_NeverPanics runs the port over every truncation of both
// vectors and over arbitrary tails: every index into the name is bounded.
func TestDecodeName4_NeverPanics(t *testing.T) {
	built := []byte("abcdef\x00\x04\xf1\x00\xff\x01\x41\x30\xc0\x7f")
	for k := range built {
		_ = decodeName4(rar4FileUnicode, built[:k])
	}
	_ = decodeName4(rar4FileUnicode, []byte{0, 0xff, 0xff, 0xff})
}

func TestParseFileHeader4_NonUTF8NameIsValidUTF8(t *testing.T) {
	fh, err := parseFileHeader(fileHeader4(t, storedSpec("\x82\x9aa")))
	if err != nil || !utf8.ValidString(fh.Name) {
		t.Fatalf("Name %q, %v; want valid UTF-8", fh.Name, err)
	}
}

func TestParseFileHeader4_NameIsSanitized(t *testing.T) {
	for raw, want := range map[string]string{"../../etc/x": "etc/x", `\a\b`: "a/b"} {
		if fh, err := parseFileHeader(fileHeader4(t, storedSpec(raw))); err != nil || fh.Name != want {
			t.Errorf("%q: Name %q, %v; want %q", raw, fh.Name, err, want)
		}
	}
}

func TestParseFileHeader4_ExtTime(t *testing.T) {
	const ftime = 0x5d57764a
	s := storedSpec("t")
	s.DOSTime = ftime
	s.Flags |= rar4FileExtTime
	s.Tail = []byte{0x00, 0xb0, 0x01, 0x02, 0x03} // mtime present, +0 s, 3 remainder bytes
	fh, err := parseFileHeader(fileHeader4(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if want := dosTime(ftime).Add(0x030201 * 100); !fh.ModificationTime.Equal(want) {
		t.Errorf("ModificationTime %v, want %v", fh.ModificationTime, want)
	}

	// Fewer bytes are the MOST significant ones: unrar shifts byte j by
	// (j+3-count)*8, so one byte lands in bits 16-23 and two in 8-23.
	for _, tc := range []struct {
		tail []byte
		rem  time.Duration
	}{
		{[]byte{0x00, 0x90, 0x05}, 0x050000},
		{[]byte{0x00, 0xa0, 0x01, 0x02}, 0x020100},
	} {
		s.Tail = tc.tail
		fh, err := parseFileHeader(fileHeader4(t, s))
		if want := dosTime(ftime).Add(tc.rem * 100); err != nil || !fh.ModificationTime.Equal(want) {
			t.Errorf("% x: ModificationTime %v, %v; want %v", tc.tail, fh.ModificationTime, err, want)
		}
	}

	s.Tail = []byte{0x00, 0xf0, 0x01} // +1 s, 3 bytes promised, 1 present
	if fh, err := parseFileHeader(fileHeader4(t, s)); fh == nil || !errors.Is(err, ErrCorruptFileHeader) {
		t.Errorf("truncated ext-time: fh %v, err %v; want the header and ErrCorruptFileHeader", fh, err)
	}
	s.Tail = []byte{0x00}
	if fh, err := parseFileHeader(fileHeader4(t, s)); fh == nil || !errors.Is(err, ErrCorruptFileHeader) {
		t.Errorf("one ext-time flag byte: fh %v, err %v; want the header and ErrCorruptFileHeader", fh, err)
	}
	s.Tail = []byte{0x00, 0xc0} // +1 s, no remainder
	if fh, err := parseFileHeader(fileHeader4(t, s)); err != nil || !fh.ModificationTime.Equal(dosTime(ftime).Add(time.Second)) {
		t.Errorf("+1 s: %v, %v", fh.ModificationTime, err)
	}
}

func TestDosTime(t *testing.T) {
	// 2026-10-23 14:50:20: year 46, month 10, day 23, 14 h, 50 min, 10 x 2 s.
	v := uint32(46)<<25 | 10<<21 | 23<<16 | 14<<11 | 50<<5 | 10
	if got, want := dosTime(v), time.Date(2026, 10, 23, 14, 50, 20, 0, time.Local); !got.Equal(want) {
		t.Fatalf("dosTime = %v, want %v", got, want)
	}
}

// TestParseFileHeader4_ShortPayload pins that a body cut anywhere before the
// end of its name is a bare refusal, with nothing to name, and never a panic.
func TestParseFileHeader4_ShortPayload(t *testing.T) {
	s := storedSpec("name.bin")
	s.Flags |= rar4FileLarge
	body := rar4File(s)[7:]
	for k := 0; k < 25+8+len(s.Name); k++ {
		h := &blockHeader{Type: headerTypeFile, Flags: uint64(s.Flags), Payload: body[:k], rar4: true}
		if fh, err := parseFileHeader(h); fh != nil || err == nil {
			t.Errorf("body cut at %d: fh %v, err %v; want nil and an error", k, fh, err)
		}
	}
}

func TestIsSymlink4(t *testing.T) {
	for _, tc := range []struct {
		host uint64
		attr uint64
		want bool
	}{{1, 0xa1ff, true}, {1, 0x81a4, false}, {0, 0xa1ff, false}} {
		if got := isSymlink4(&FileHeader{HostOS: tc.host, Attributes: tc.attr}); got != tc.want {
			t.Errorf("HostOS %d attr %#x: %v, want %v", tc.host, tc.attr, got, tc.want)
		}
	}
}

func TestReadLinkTarget4(t *testing.T) {
	link := func(target string) *FileHeader {
		n := int64(len(target))
		return &FileHeader{
			Name: "l", FirstBlock: true, LastBlock: true, PackedSize: n, UnpackedSize: n,
			CRC32: crc32.ChecksumIEEE([]byte(target)), HasCRC32: true,
		}
	}

	fh := link("../x")
	if err := readLinkTarget4(fh, bytes.NewReader([]byte("../x"))); err != nil {
		t.Fatalf("readLinkTarget4: %v", err)
	}
	if fh.LinkType != LinkUnixSymlink || fh.LinkTarget != "../x" {
		t.Fatalf("LinkType %v LinkTarget %q; want a Unix symlink to the raw ../x", fh.LinkType, fh.LinkTarget)
	}

	long := string(bytes.Repeat([]byte("a"), maxLinkTarget4+1))
	for _, tc := range []struct {
		name   string
		fh     func() *FileHeader
		src    string
		target error
	}{
		{"split before", func() *FileHeader { f := link("x"); f.FirstBlock = false; return f }, "x", ErrCorruptFileHeader},
		{"split after", func() *FileHeader { f := link("x"); f.LastBlock = false; return f }, "x", ErrCorruptFileHeader},
		{"packed != unpacked", func() *FileHeader { f := link("x"); f.UnpackedSize = 2; return f }, "x", ErrCorruptFileHeader},
		{"empty", func() *FileHeader { return link("") }, "", ErrCorruptFileHeader},
		{"over the cap", func() *FileHeader { return link(long) }, long, ErrCorruptFileHeader},
		{"short source", func() *FileHeader { return link("abcd") }, "ab", ErrTruncatedFile},
		{"CRC wrong", func() *FileHeader { f := link("abcd"); f.CRC32++; return f }, "abcd", ErrCRCMismatch},
		{"NUL in target", func() *FileHeader { return link("a\x00b") }, "a\x00b", ErrCorruptFileHeader},
	} {
		fh := tc.fh()
		err := readLinkTarget4(fh, bytes.NewReader([]byte(tc.src)))
		if !errors.Is(err, tc.target) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.target)
		}
		if fh.LinkType != LinkNone || fh.LinkTarget != "" {
			t.Errorf("%s: refused, but LinkType %v LinkTarget %q were set", tc.name, fh.LinkType, fh.LinkTarget)
		}
	}
}
