package rarengine

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"testing"
)

// RAR 1.5-4.x archive construction for the test suite, the counterpart of
// testbuild_test.go. Every block goes through rar4Block, and rar4File is the
// one file-header layout; TestRAR4BuilderMatchesRealHeader holds both to what
// rar 6.24 writes.

// rar4Sig is the RAR 1.5-4.x marker block.
var rar4Sig = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}

// rar4Block frames a header body: HEAD_CRC, type, flags and HEAD_SIZE, where
// HEAD_CRC is the low 16 bits of the CRC32 over everything after it. It
// writes flags as given and computes nothing a caller states.
func rar4Block(typ byte, flags uint16, body []byte) []byte {
	b := make([]byte, 7, 7+len(body))
	b[2] = typ
	binary.LittleEndian.PutUint16(b[3:], flags)
	binary.LittleEndian.PutUint16(b[5:], uint16(7+len(body)))
	b = append(b, body...)
	binary.LittleEndian.PutUint16(b[0:], uint16(crc32.ChecksumIEEE(b[2:])))
	return b
}

// rar4MainHeader is the archive header: HighPosAV and PosAV, both zero.
func rar4MainHeader(flags uint16) []byte { return rar4Block(0x73, flags, make([]byte, 6)) }

// rar4EndHeader terminates a volume with the flags rar writes on a single one.
func rar4EndHeader() []byte { return rar4Block(0x7b, 0x4000, nil) }

// rar4FileSpec is every field of a RAR4 file header. Flags is written as
// given, so LHD_LONG_BLOCK (0x8000), which rar always sets on a file header,
// is the caller's to state; PackHigh and UnpHigh are written only when Flags
// carries LHD_LARGE (0x0100). Tail follows the name: salt, extended time.
type rar4FileSpec struct {
	Name                               []byte
	Flags                              uint16
	PackLow, PackHigh, UnpLow, UnpHigh uint32
	HostOS                             byte
	CRC                                uint32
	DOSTime                            uint32
	UnpVer, Method                     byte
	Attr                               uint32
	Tail                               []byte
}

// rar4File builds the 0x74 header for s. The payload is not included: append
// it as the next block, or leave it out to cut the volume there.
func rar4File(s rar4FileSpec) []byte {
	le := binary.LittleEndian
	body := make([]byte, 25, 25+8+len(s.Name)+len(s.Tail))
	le.PutUint32(body[0:], s.PackLow)
	le.PutUint32(body[4:], s.UnpLow)
	body[8] = s.HostOS
	le.PutUint32(body[9:], s.CRC)
	le.PutUint32(body[13:], s.DOSTime)
	body[17] = s.UnpVer
	body[18] = s.Method
	le.PutUint16(body[19:], uint16(len(s.Name)))
	le.PutUint32(body[21:], s.Attr)
	if s.Flags&0x0100 != 0 {
		body = le.AppendUint32(body, s.PackHigh)
		body = le.AppendUint32(body, s.UnpHigh)
	}
	body = append(body, s.Name...)
	body = append(body, s.Tail...)
	return rar4Block(0x74, s.Flags, body)
}

// rar4Archive is one complete volume: the signature, a main header with no
// flags, blocks in order, and an end header.
func rar4Archive(blocks ...[]byte) []byte { return rar4Volume(0, blocks...) }

// rar4Volume is rar4Archive with the main header's flags given: solid, or one
// volume of a set.
func rar4Volume(mainFlags uint16, blocks ...[]byte) []byte {
	out := append(append([]byte{}, rar4Sig...), rar4MainHeader(mainFlags)...)
	for _, b := range blocks {
		out = append(out, b...)
	}
	return append(out, rar4EndHeader()...)
}

// TestRAR4BuilderMatchesRealHeader pins that the RAR4 builder writes what rar
// writes: rar4_store.rar, taken apart by hand and put back together from the
// decoded fields, must come back byte for byte -- HEAD_CRC, HEAD_SIZE and the
// main and end headers included. A builder that drifted from the format would
// otherwise let every test built on it agree with the parser about a layout no
// real archive has.
func TestRAR4BuilderMatchesRealHeader(t *testing.T) {
	arc, err := os.ReadFile("testdata/rar4_store.rar")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(arc, rar4Sig) {
		t.Fatalf("fixture does not open with the RAR4 signature: % x", arc[:7])
	}

	var blocks [][]byte
	sawMain, sawEnd := false, false
	for off := len(rar4Sig); off < len(arc); {
		typ := arc[off+2]
		flags := binary.LittleEndian.Uint16(arc[off+3:])
		size := int(binary.LittleEndian.Uint16(arc[off+5:]))
		body := arc[off+7 : off+size]
		switch typ {
		case 0x73:
			if flags != 0 || !bytes.Equal(body, make([]byte, 6)) {
				t.Fatalf("main header flags %#x body % x; the builder writes flags 0 and six zero bytes", flags, body)
			}
			sawMain = true
		case 0x74:
			s := decodeRAR4FileSpec(t, flags, body)
			payload := arc[off+size : off+size+int(s.PackLow)]
			blocks = append(blocks, rar4File(s), payload)
			off += int(s.PackLow)
		case 0x7b:
			sawEnd = true
		default:
			t.Fatalf("unexpected block type %#x in rar4_store.rar", typ)
		}
		off += size
	}
	if !sawMain || !sawEnd || len(blocks) != 4 {
		t.Fatalf("main=%v end=%v members=%d; want a main header, an end header and two members",
			sawMain, sawEnd, len(blocks)/2)
	}

	if got := rar4Archive(blocks...); !bytes.Equal(got, arc) {
		t.Fatalf("rebuilt archive differs from rar's:\n got  % x\n want % x", got, arc)
	}
}

// decodeRAR4FileSpec reads a stored file header body back into the spec that
// would build it. Only the shapes rar4_store.rar holds are decoded: no LARGE
// sizes, no salt, no extended time, so anything after the name is Tail.
func decodeRAR4FileSpec(t *testing.T, flags uint16, body []byte) rar4FileSpec {
	t.Helper()
	if flags&0x0100 != 0 {
		t.Fatalf("file header flags %#x carry LHD_LARGE; this decoder does not read it", flags)
	}
	le := binary.LittleEndian
	nameLen := int(le.Uint16(body[19:]))
	return rar4FileSpec{
		Name:    body[25 : 25+nameLen],
		Flags:   flags,
		PackLow: le.Uint32(body[0:]),
		UnpLow:  le.Uint32(body[4:]),
		HostOS:  body[8],
		CRC:     le.Uint32(body[9:]),
		DOSTime: le.Uint32(body[13:]),
		UnpVer:  body[17],
		Method:  body[18],
		Attr:    le.Uint32(body[21:]),
		Tail:    body[25+nameLen:],
	}
}
