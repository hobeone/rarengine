package rarengine

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

// unrarFilterE8 is unpack50.cpp's ApplyFilter FILTER_E8 case, transcribed
// literally: same uint narrowing, same raw-bit sign tests, same order.
//
// It is the oracle for the test below because the property under test is not
// "does this look right" but "does this agree with the reference decoder at
// output positions no fixture can reach". Every deviation from the C is a
// place this test would stop proving that, so it deliberately keeps unrar's
// shape rather than idiomatic Go -- including CurPos+4<DataSize instead of
// DataSize-4, which unrar notes is to avoid underflow for DataSize<4.
func unrarFilterE8(cmpByte2 byte, data []byte, writtenFileSize int64) []byte {
	out := append([]byte(nil), data...)
	fileOffset := uint32(writtenFileSize)
	const fs = uint32(0x1000000)

	d := 0
	for curPos := uint32(0); curPos+4 < uint32(len(out)); {
		curByte := out[d]
		d++
		curPos++
		if curByte == 0xe8 || curByte == cmpByte2 {
			offset := (curPos + fileOffset) % fs
			addr := binary.LittleEndian.Uint32(out[d:])
			if addr&0x80000000 != 0 {
				if (addr+offset)&0x80000000 == 0 {
					binary.LittleEndian.PutUint32(out[d:], addr+fs)
				}
			} else if (addr-fs)&0x80000000 != 0 {
				binary.LittleEndian.PutUint32(out[d:], addr-offset)
			}
			d += 4
			curPos += 4
		}
	}
	return out
}

// e8Corpus builds a buffer dense in E8/E9 bytes with a spread of address
// values, including ones on both sides of the 0x80000000 and fileSize
// boundaries the branches turn on.
func e8Corpus(seed int64, n int) []byte {
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, 0, n*8)
	addrs := []uint32{
		0, 1, 0x00ffffff, 0x01000000, 0x01000001,
		0x7fffffff, 0x80000000, 0x80000001, 0xffffffff,
	}
	for range n {
		switch rng.Intn(3) {
		case 0:
			buf = append(buf, 0xe8)
		case 1:
			buf = append(buf, 0xe9)
		default:
			buf = append(buf, byte(rng.Intn(256)))
		}
		var a [4]byte
		v := addrs[rng.Intn(len(addrs))]
		if rng.Intn(2) == 0 {
			v = rng.Uint32()
		}
		binary.LittleEndian.PutUint32(a[:], v)
		buf = append(buf, a[:]...)
	}
	return buf
}

// TestFilterE8MatchesUnrarAcrossOutputPositions is the regression test for the
// 2 GB defect, driven at the filter rather than through an archive.
//
// A fixture large enough to push d.tot past 2 GB is impractical to commit, and
// the arithmetic does not need one: filterE8 takes the output position as a
// parameter, so the positions that matter can simply be passed in. This is the
// approach issue #20 proposed and it is the right one -- the bug was never in
// the archive, only in what the running position became.
//
// Mutation check: restore `off := int32(offset)` and this fails at the first
// offset past 2 GB that is not a multiple of 0x1000000.
func TestFilterE8MatchesUnrarAcrossOutputPositions(t *testing.T) {
	for _, cmpByte2 := range []byte{0xe8, 0xe9} {
		for _, off := range []int64{
			0, 1, 4095, 1 << 20,
			1<<24 - 1, 1 << 24, 1<<24 + 1, // fileSize boundary
			1 << 30,
			1<<31 - 1, 1 << 31, 1<<31 + 1, // int32 sign boundary: the defect
			1<<31 + 12345,
			1<<32 - 1, 1 << 32, 1<<32 + 999, // uint32 wrap
			1 << 40,
			1<<40 + 7654321,
		} {
			data := e8Corpus(off^int64(cmpByte2), 500)
			want := unrarFilterE8(cmpByte2, data, off)
			got := filterE8(cmpByte2, append([]byte(nil), data...), off)
			if !bytes.Equal(got, want) {
				diff := -1
				for i := range got {
					if got[i] != want[i] {
						diff = i
						break
					}
				}
				t.Fatalf("cmpByte2=%#x offset=%d: diverges from unrar at byte %d "+
					"(got %#x want %#x)", cmpByte2, off, diff, got[diff], want[diff])
			}
		}
	}
}

// The same agreement over randomised offsets, so the boundary list above is a
// floor rather than the whole assertion.
func TestFilterE8MatchesUnrarOnRandomOffsets(t *testing.T) {
	rng := rand.New(rand.NewSource(20))
	for i := range 300 {
		off := rng.Int63n(1 << 42)
		data := e8Corpus(int64(i), 200)
		want := unrarFilterE8(0xe9, data, off)
		got := filterE8(0xe9, append([]byte(nil), data...), off)
		if !bytes.Equal(got, want) {
			t.Fatalf("offset=%d diverges from unrar", off)
		}
	}
}
