package rarengine

import (
	"errors"
)

// ErrTruncatedVint is returned when a vint is incomplete or exceeds the maximum length of 10 bytes.
var ErrTruncatedVint = errors.New("rarengine: truncated vint")

// DecodeVint decodes a RAR5 variable-length integer from a byte slice,
// returning the decoded uint64 and the number of bytes consumed.
// A valid vint is at most 10 bytes long.
func DecodeVint(b []byte) (uint64, int, error) {
	const maxVintBytes = 10
	var x uint64
	var s uint

	for i, n := range b {
		if i >= maxVintBytes {
			return 0, 0, ErrTruncatedVint
		}
		if n < 0x80 {
			return x | uint64(n)<<s, i + 1, nil
		}
		x |= uint64(n&0x7f) << s
		s += 7
	}
	return 0, 0, ErrTruncatedVint
}

// EncodeVint encodes a uint64 into a RAR5 variable-length integer,
// returning the encoded bytes.
func EncodeVint(v uint64) []byte {
	var buf [10]byte
	i := 0
	for v >= 0x80 {
		buf[i] = byte(v | 0x80)
		v >>= 7
		i++
	}
	buf[i] = byte(v)
	return buf[:i+1]
}
