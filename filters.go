package rarengine

import (
	"encoding/binary"
)

var (
	filterArmSIMD    func(buf []byte, offset int64) int
	filterE8ScanSIMD func(buf []byte, c byte) int
)

const fileSize = 0x1000000

// FilterDelta computes cumulative striped byte differences.
func FilterDelta(n int, buf []byte) []byte {
	if n <= 0 || n > len(buf) {
		return buf
	}
	res := make([]byte, len(buf))
	i := 0
	for j := 0; j < n; j++ {
		var c byte
		for k := j; k < len(res); k += n {
			c -= buf[i]
			i++
			res[k] = c
		}
	}
	return res
}

// FilterArm relocates branch offsets in ARM machine code.
func FilterArm(buf []byte, offset int64) []byte {
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

// FilterE8 relocates relative CALL/JMP offset addresses to absolute offsets in x86 executables.
func FilterE8(c byte, v5 bool, buf []byte, offset int64) []byte {
	off := int32(offset)
	for b := buf; len(b) >= 5; {
		if filterE8ScanSIMD != nil && len(b) >= 32 {
			idx := filterE8ScanSIMD(b, c)
			if idx > 0 {
				if idx > len(b)-5 {
					idx = len(b)
				}
				off += int32(idx)
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
		if v5 {
			off %= fileSize
		}
		addr := int32(binary.LittleEndian.Uint32(b))
		if addr < 0 {
			if addr+off >= 0 {
				binary.LittleEndian.PutUint32(b, uint32(addr+fileSize))
			}
		} else if addr < fileSize {
			binary.LittleEndian.PutUint32(b, uint32(addr-off))
		}
		off += 4
		b = b[4:]
	}
	return buf
}
