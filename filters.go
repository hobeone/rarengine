package rarengine

import (
	"encoding/binary"
)

var (
	filterArmSIMD    func(buf []byte, offset int64) int
	filterE8ScanSIMD func(buf []byte, c byte) int
)

const fileSize = 0x1000000

// filterDelta computes cumulative striped byte differences.
func filterDelta(n int, buf []byte, out []byte) []byte {
	if n <= 0 || n > len(buf) {
		return buf
	}
	if len(out) < len(buf) {
		out = make([]byte, len(buf))
	} else {
		out = out[:len(buf)]
	}
	i := 0
	for j := range n {
		var c byte
		for k := j; k < len(out); k += n {
			c -= buf[i]
			i++
			out[k] = c
		}
	}
	return out
}

// filterArm relocates branch offsets in ARM machine code.
func filterArm(buf []byte, offset int64) []byte {
	var start int
	if filterArmSIMD != nil && len(buf) >= 32 {
		start = filterArmSIMD(buf, offset)
	}
	for i := start; len(buf)-i > 3; i += 4 {
		if buf[i+3] == 0xeb {
			n := uint(buf[i])
			n += uint(buf[i+1]) * 0x100
			n += uint(buf[i+2]) * 0x10000
			n -= (uint(offset) + uint(i)) / 4
			buf[i] = byte(n)
			buf[i+1] = byte(n >> 8)
			buf[i+2] = byte(n >> 16)
		}
	}
	return buf
}

// filterE8 relocates relative CALL/JMP offsets to absolute ones.
//
// The running position is uint32, not int32, and that is the whole of what
// this function gets right. unrar narrows the same 64-bit value the same way
// -- `uint FileOffset=(uint)WrittenFileSize` -- and the narrowing is exact,
// because fileSize is 2^24 and 2^24 divides 2^32, so (x mod 2^32) mod 2^24
// equals x mod 2^24. Width is not the hazard.
//
// Signedness is. With an int32 running position, Go's % returns a NEGATIVE
// remainder for a negative operand, so past 2 GB of output the offset came
// out 2^24 too small -- except when it landed exactly on a multiple of 2^24,
// where it agreed by accident. That intermittency is why nothing caught it.
//
// The sign tests below are written against the raw bits the way unrar writes
// them, for the same reason unrar gives: they must not depend on a signed
// type being present or on its width.
func filterE8(c byte, buf []byte, offset int64) []byte {
	off := uint32(offset)
	for b := buf; len(b) >= 5; {
		if filterE8ScanSIMD != nil && len(b) >= 32 {
			idx := filterE8ScanSIMD(b, c)
			if idx > 0 {
				if idx > len(b)-5 {
					idx = len(b)
				}
				off += uint32(idx)
				b = b[idx:]
				if len(b) < 5 {
					break
				}
			}
		}

		ch := b[0]
		b = b[1:]
		off++
		if ch != 0xe8 && ch != c {
			continue
		}
		// Computed fresh rather than folded back into off, matching
		// unrar's `Offset=(CurPos+FileOffset)%FileSize`. Both are congruent
		// mod 2^24 and only that matters, but keeping off unreduced makes it
		// the position rather than a residue.
		cur := off % fileSize
		addr := binary.LittleEndian.Uint32(b)
		if addr&0x80000000 != 0 { // addr would be negative as int32
			if (addr+cur)&0x80000000 == 0 { // addr+cur >= 0
				binary.LittleEndian.PutUint32(b, addr+fileSize)
			}
		} else if addr < fileSize {
			binary.LittleEndian.PutUint32(b, addr-cur)
		}
		off += 4
		b = b[4:]
	}
	return buf
}
