package rarengine

import (
	"errors"
	"io"
)

// ErrDecoderOutOfData is returned when the decompressor requests more bits than available in the block.
var ErrDecoderOutOfData = errors.New("rarengine: decoder out of data")

// BitReader is an optimized, allocation-free, MSB-first 64-bit buffered bit reader.
type BitReader struct {
	buf      []byte // Source data slice
	off      int    // Current byte index in buf
	v        uint64 // 64-bit bit cache
	n        uint8  // Number of valid bits in v
	limit    int    // Maximum number of bits we are allowed to read from this block
	bitsRead int    // Total number of bits read so far
}

// NewBitReader initializes a new bit reader with the given byte slice and bit limit.
func NewBitReader(buf []byte, limitBits int) *BitReader {
	return &BitReader{
		buf:   buf,
		limit: limitBits,
	}
}

// Reset reuses an existing BitReader with a new source buffer and bit limit.
// All internal state (cache, byte offset, bits-read counter) is cleared.
func (r *BitReader) Reset(buf []byte, limitBits int) {
	r.buf = buf
	r.off = 0
	r.v = 0
	r.n = 0
	r.limit = limitBits
	r.bitsRead = 0
}

// fill refills the bit buffer v so it contains up to 56 bits.
func (r *BitReader) fill() {
	for r.n <= 56 && r.off < len(r.buf) {
		r.v = (r.v << 8) | uint64(r.buf[r.off])
		r.n += 8
		r.off++
	}
}

// ReadBits reads k bits from the stream and advances the pointer (k <= 32).
func (r *BitReader) ReadBits(k uint8) (int, error) {
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
func (r *BitReader) PeekBits(k uint8) uint32 {
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
func (r *BitReader) Advance(k uint8) {
	r.n -= k
	r.bitsRead += int(k)
}

// AlignByte aligns the current bit stream to the next byte boundary.
func (r *BitReader) AlignByte() {
	discard := r.n % 8
	r.v >>= discard
	r.n -= discard
	r.bitsRead += int(discard)
}

// ReadByte reads a single byte from the bit reader.
func (r *BitReader) ReadByte() (byte, error) {
	val, err := r.ReadBits(8)
	return byte(val), err
}

// BitsRead returns the total number of bits read.
func (r *BitReader) BitsRead() int {
	return r.bitsRead
}
