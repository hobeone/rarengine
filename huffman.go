package rarengine

import (
	"errors"
	"io"
)

const (
	maxCodeLength = 15 // maximum code length in bits
	maxQuickBits  = 10
	maxQuickSize  = 1 << maxQuickBits
)

var (
	ErrHuffDecodeFailed   = errors.New("rarengine: huffman decode failed")
	ErrInvalidLengthTable = errors.New("rarengine: invalid huffman code length table")
)

type huffmanDecoder struct {
	limit     [maxCodeLength + 1]uint16
	pos       [maxCodeLength + 1]uint16
	symbol    []uint16
	min       uint8
	quickbits uint8
	quicklen  [maxQuickSize]uint8
	quicksym  [maxQuickSize]uint16
}

// Init initializes the Huffman tables using the given code symbol bitlengths.
// It returns an error if the Huffman code length table defines an over-subscribed (invalid) tree.
func (h *huffmanDecoder) Init(codeLengths []byte) error {
	var count [maxCodeLength + 1]uint16

	for _, n := range codeLengths {
		if n == 0 {
			continue
		}
		if int(n) > maxCodeLength {
			return ErrInvalidLengthTable
		}
		count[n]++
	}

	// Validate tree completeness (Kraft-McMillan inequality)
	var sum uint32
	for i := 1; i <= maxCodeLength; i++ {
		sum += uint32(count[i]) << (maxCodeLength - i)
	}
	if sum > 32768 {
		return ErrInvalidLengthTable
	}

	h.pos[0] = 0
	h.limit[0] = 0
	h.min = 0
	for i := uint8(1); i <= maxCodeLength; i++ {
		h.limit[i] = h.limit[i-1] + count[i]<<(maxCodeLength-i)
		h.pos[i] = h.pos[i-1] + count[i-1]
		if h.min == 0 && h.limit[i] > 0 {
			h.min = i
		}
	}

	if cap(h.symbol) >= len(codeLengths) {
		h.symbol = h.symbol[:len(codeLengths)]
		clear(h.symbol)
	} else {
		h.symbol = make([]uint16, len(codeLengths))
	}

	copy(count[:], h.pos[:])
	for i, n := range codeLengths {
		if n != 0 {
			h.symbol[count[n]] = uint16(i)
			count[n]++
		}
	}

	if len(codeLengths) >= 298 {
		h.quickbits = maxQuickBits
	} else {
		h.quickbits = maxQuickBits - 3
	}

	bits := uint8(1)
	for i := uint16(0); i < 1<<h.quickbits; i++ {
		v := i << (maxCodeLength - h.quickbits)

		for v >= h.limit[bits] && bits < maxCodeLength {
			bits++
		}
		h.quicklen[i] = bits

		dist := v - h.limit[bits-1]
		dist >>= (maxCodeLength - bits)

		pos := int(h.pos[bits]) + int(dist)
		if pos < len(h.symbol) {
			h.quicksym[i] = h.symbol[pos]
		} else {
			h.quicksym[i] = 0
		}
	}
	return nil
}

// ReadSym decodes a single symbol from the bit stream using direct lookup tables.
func (h *huffmanDecoder) ReadSym(r *bitReader) (int, error) {
	if h.min == 0 {
		return 0, ErrHuffDecodeFailed
	}
	if r.bitsRead >= r.limit {
		return 0, io.EOF
	}
	// Peek up to maxCodeLength bits to perform fast decoding
	v := uint16(r.PeekBits(maxCodeLength))

	var bits uint8
	if v < h.limit[h.quickbits] {
		i := v >> (maxCodeLength - h.quickbits)
		bits = h.quicklen[i]
		if r.bitsRead+int(bits) > r.limit {
			return 0, io.EOF
		}
		r.Advance(bits)
		return int(h.quicksym[i]), nil
	}

	for bits = h.min; bits < maxCodeLength; bits++ {
		if v < h.limit[bits] {
			break
		}
	}
	if r.bitsRead+int(bits) > r.limit {
		return 0, io.EOF
	}
	r.Advance(bits)

	dist := v - h.limit[bits-1]
	dist >>= maxCodeLength - bits

	pos := int(h.pos[bits]) + int(dist)
	if pos >= len(h.symbol) {
		return 0, ErrHuffDecodeFailed
	}

	return int(h.symbol[pos]), nil
}

// readCodeLengthTable reads a dynamic code length table from the bit stream.
// The scratch huffmanDecoder is used to decode the 20-symbol bit-length table;
// callers should reuse a single scratch across calls to avoid per-block allocations.
func readCodeLengthTable(br *bitReader, codeLength []byte, scratch *huffmanDecoder) error {
	var bitlength [20]byte
	for i := 0; i < len(bitlength); i++ {
		n, err := br.ReadBits(4)
		if err != nil {
			return err
		}
		if n == 0xf {
			cnt, err := br.ReadBits(4)
			if err != nil {
				return err
			}
			if cnt > 0 {
				i += cnt + 1
				continue
			}
		}
		bitlength[i] = byte(n)
	}

	if err := scratch.Init(bitlength[:]); err != nil {
		return err
	}

	for i := 0; i < len(codeLength); i++ {
		l, err := scratch.ReadSym(br)
		if err != nil {
			return err
		}

		if l < 16 {
			codeLength[i] = byte(l)
			continue
		}

		var count int
		var value byte

		switch l {
		case 16, 18:
			count, err = br.ReadBits(3)
			count += 3
		default:
			count, err = br.ReadBits(7)
			count += 11
		}
		if err != nil {
			return err
		}
		if l < 18 {
			if i == 0 {
				return ErrInvalidLengthTable
			}
			value = codeLength[i-1]
		}
		for ; count > 0 && i < len(codeLength); i++ {
			codeLength[i] = value
			count--
		}
		i--
	}
	return nil
}
