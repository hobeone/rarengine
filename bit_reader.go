package rarengine

import (
	"encoding/binary"
	"errors"
	"io"
)

// ErrDecoderOutOfData is returned when the decompressor requests more bits than available in the block.
var ErrDecoderOutOfData = errors.New("rarengine: decoder out of data")

// bitReader is an optimized, allocation-free, MSB-first 64-bit buffered bit reader.
type bitReader struct {
	buf      []byte // Source data slice
	off      int    // Current byte index in buf
	v        uint64 // 64-bit bit cache
	n        uint8  // Number of valid bits in v
	limit    int    // Maximum number of bits we are allowed to read from this block
	bitsRead int    // Total number of bits read so far
}

// newBitReader initializes a new bit reader with the given byte slice and bit limit.
func newBitReader(buf []byte, limitBits int) *bitReader {
	return &bitReader{
		buf:   buf,
		limit: limitBits,
	}
}

// Reset reuses an existing BitReader with a new source buffer and bit limit.
// All internal state (cache, byte offset, bits-read counter) is cleared.
func (r *bitReader) Reset(buf []byte, limitBits int) {
	r.buf = buf
	r.off = 0
	r.v = 0
	r.n = 0
	r.limit = limitBits
	r.bitsRead = 0
}

// fill refills the bit buffer v so it contains 57-64 valid bits.
//
// Hot path: when at least 8 bytes remain, load them as a single big-endian
// uint64 (a single MOVBEQ on amd64) and merge the high `bitsToAdd` bits into
// r.v in one shift/OR. Bytes past `bitsToAdd/8` are not consumed; they're
// re-read next call. The end-of-buffer fallback (byte-by-byte for the final
// <8 bytes) lives in fillTail to keep this function focused on the hot case.
func (r *bitReader) fill() {
	if r.n > 56 {
		return
	}
	if r.off+8 > len(r.buf) {
		r.fillTail()
		return
	}
	bytesToAdd := (64 - r.n) >> 3 // in [1, 8]
	bitsToAdd := bytesToAdd << 3  // in [8, 64]
	u := binary.BigEndian.Uint64(r.buf[r.off:])
	r.v = (r.v << bitsToAdd) | (u >> (64 - bitsToAdd))
	r.n += bitsToAdd
	r.off += int(bytesToAdd)
}

// fillTail handles the final <8 bytes of the buffer where the bulk uint64
// load would read out of bounds.
func (r *bitReader) fillTail() {
	for r.n <= 56 && r.off < len(r.buf) {
		r.v = (r.v << 8) | uint64(r.buf[r.off])
		r.n += 8
		r.off++
	}
}

// ReadBits reads k bits from the stream and advances the pointer (k <= 32).
func (r *bitReader) ReadBits(k uint8) (int, error) {
	if r.bitsRead+int(k) > r.limit {
		return 0, io.EOF
	}
	if r.n < k {
		r.fill()
		if r.n < k {
			return 0, ErrDecoderOutOfData
		}
	}
	r.n -= k
	val := int((r.v >> r.n) & ((1 << k) - 1))
	r.bitsRead += int(k)
	return val, nil
}

// PeekBits returns k bits from the stream without advancing the pointer (k <= 24).
func (r *bitReader) PeekBits(k uint8) uint32 {
	if r.n < k {
		r.fill()
	}
	if r.n < k {
		shift := k - r.n
		return uint32((r.v & ((1 << r.n) - 1)) << shift)
	}
	return uint32((r.v >> (r.n - k)) & ((1 << k) - 1))
}

// Advance moves the stream pointer forward by k bits.
func (r *bitReader) Advance(k uint8) {
	r.n -= k
	r.bitsRead += int(k)
}

// ReadByte reads a single byte from the bit reader.
func (r *bitReader) ReadByte() (byte, error) {
	val, err := r.ReadBits(8)
	return byte(val), err
}
