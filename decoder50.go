package rarengine

import (
	"errors"
	"io"
)

var (
	ErrUnknownFilter       = errors.New("rarengine: unknown V5 filter")
	ErrCorruptDecodeHeader = errors.New("rarengine: corrupt decode header")
	ErrTooManyFilters      = errors.New("rarengine: too many queued filters")
	ErrInvalidFilter       = errors.New("rarengine: invalid filter offset/length")
)

const (
	mainSize5      = 306
	offsetSize5    = 64
	lowoffsetSize5 = 16
	lengthSize5    = 44
	tableSize5     = mainSize5 + offsetSize5 + lowoffsetSize5 + lengthSize5

	maxQueuedFilters = 1024

	// maxFilterBlockSize bounds a filter block's declared length. It matches
	// unrar's limit, though unrar neutralizes an oversize block where this
	// rejects it, so behavior on corrupt input differs from that reference.
	maxFilterBlockSize = 0x400000
)

// FilterBlock holds parameters for post-processing execution.
type FilterBlock struct {
	// start is the block's absolute position in this file's output stream,
	// comparable against tot. Absolute rather than relative to the previous
	// filter so that draining needs no running decrement, and so a filter
	// queued while an earlier block is being staged needs no compensation.
	start  int64
	length int
	ftype  uint8 // 0: Delta, 1: E8, 2: E9, 3: Arm
	param  uint8 // Stores 'n' for Delta filter
}

// decoder50 manages the LZ77 dynamic decompression state machine.
type decoder50 struct {
	r          io.Reader
	br         *BitReader // points to bitReader when a block is loaded; nil between blocks
	bitReader  BitReader  // reusable bit reader (embedded to avoid per-block allocations)
	payloadBuf []byte     // reusable scratch buffer for compressed block payload
	codeLength [tableSize5]byte
	lastBlock  bool
	offsetSize int

	mainDecoder      HuffmanDecoder
	offsetDecoder    HuffmanDecoder
	lowoffsetDecoder HuffmanDecoder
	lengthDecoder    HuffmanDecoder
	bitlenDecoder    HuffmanDecoder // scratch for ReadCodeLengthTable

	offset [4]int
	length int

	fl           []FilterBlock
	outbuf       []byte // Leftover filter output that didn't fit in the caller's buffer
	filterBuf    []byte // Reusable scratch for filter input; reused once outbuf drains
	filterOutBuf []byte // Reusable scratch for filter output
	tot          int64  // Total number of bytes read/output so far
	// decoded counts bytes written into the window for this file. It runs ahead
	// of tot by whatever is decoded but not yet emitted, and the two must share
	// an epoch: init resets both, or neither, so a queued filter's start stays
	// comparable against tot. Resetting one alone silently mispositions every
	// queued filter.
	decoded int64
}

func newDecoder50() *decoder50 {
	return &decoder50{
		offsetSize: offsetSize5,
		fl:         make([]FilterBlock, 0, maxQueuedFilters),
	}
}

// init prepares the decoder state.
func (d *decoder50) init(r io.Reader, reset bool) {
	d.r = r
	d.lastBlock = false
	d.offsetSize = offsetSize5
	if reset {
		for i := range d.offset {
			d.offset[i] = 0
		}
		d.length = 0
		for i := range d.codeLength {
			d.codeLength[i] = 0
		}
		if d.fl != nil {
			d.fl = d.fl[:0]
		}
		d.outbuf = nil
		d.tot = 0
		d.decoded = 0
	}
}

// readBlockHeader parses block bit limits and dynamic Huffman tables from the stream.
func (d *decoder50) readBlockHeader() error {
	var temp [2]byte
	_, err := io.ReadFull(d.r, temp[:])
	if err != nil {
		return err
	}
	flags := temp[0]
	hsum := temp[1]

	bytecount := (flags>>3)&3 + 1
	if bytecount == 4 {
		return ErrCorruptDecodeHeader
	}

	blockBits := int(flags)&0x07 + 1
	blockBytes := 0
	sum := 0x5a ^ flags

	var blockBytesBuf [3]byte
	_, err = io.ReadFull(d.r, blockBytesBuf[:bytecount])
	if err != nil {
		return err
	}

	for i := range bytecount {
		n := blockBytesBuf[i]
		sum ^= n
		blockBytes |= int(n) << (i * 8)
	}

	if sum != hsum {
		return ErrCorruptDecodeHeader
	}

	blockBits += (blockBytes - 1) * 8

	if cap(d.payloadBuf) < blockBytes {
		d.payloadBuf = make([]byte, blockBytes)
	} else {
		d.payloadBuf = d.payloadBuf[:blockBytes]
	}
	_, err = io.ReadFull(d.r, d.payloadBuf)
	if err != nil {
		return err
	}

	d.bitReader.Reset(d.payloadBuf, blockBits)
	d.br = &d.bitReader
	d.lastBlock = flags&0x40 > 0

	if flags&0x80 > 0 {
		err = ReadCodeLengthTable(d.br, d.codeLength[:], false, &d.bitlenDecoder)
		if err != nil {
			return err
		}
		cl := d.codeLength[:]
		if err = d.mainDecoder.Init(cl[:mainSize5]); err != nil {
			return err
		}
		cl = cl[mainSize5:]
		if err = d.offsetDecoder.Init(cl[:d.offsetSize]); err != nil {
			return err
		}
		cl = cl[d.offsetSize:]
		if err = d.lowoffsetDecoder.Init(cl[:lowoffsetSize5]); err != nil {
			return err
		}
		cl = cl[lowoffsetSize5:]
		if err = d.lengthDecoder.Init(cl); err != nil {
			return err
		}
	}

	return nil
}

func slotToLength(br *BitReader, n int) (int, error) {
	if n >= 8 {
		bits := uint8(n/4 - 1)
		n = (4 | (n & 3)) << bits
		if bits > 0 {
			b, err := br.ReadBits(bits)
			if err != nil {
				return 0, err
			}
			n |= b
		}
	}
	n += 2
	return n, nil
}

// readFilter5Data reads a filter record's variable-width value: a 2-bit count
// of bytes, then that many little-endian bytes.
//
// The result is int64 rather than int so that four bytes with the top bit set
// stay positive on 32-bit platforms. As an int they would be negative, and a
// negative length reaches a slice expression while a negative offset places a
// filter behind the emission cursor.
func readFilter5Data(br *BitReader) (int64, error) {
	bytesVal, err := br.ReadBits(2)
	if err != nil {
		return 0, err
	}
	bytesVal++

	var data int64
	for i := 0; i < bytesVal; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		data |= int64(b) << (uint(i) * 8)
	}
	return data, nil
}

func (d *decoder50) readFilter(win *Window) error {
	if len(d.fl) >= maxQueuedFilters {
		return ErrTooManyFilters
	}

	var err error
	offset, err := readFilter5Data(d.br)
	if err != nil {
		return err
	}
	length, err := readFilter5Data(d.br)
	if err != nil {
		return err
	}
	ftype, err := d.br.ReadBits(3)
	if err != nil {
		return err
	}

	// Bound both stream-supplied values, which reach 0xFFFFFFFF. A filter is
	// announced while the decoder is near its position, so an offset beyond one
	// window is malformed rather than merely distant. Both are non-negative by
	// construction, so an upper bound is the whole check.
	if length > maxFilterBlockSize || offset > int64(win.size) {
		return ErrInvalidFilter
	}

	// The filter starts offset bytes past the decode head, which is where the
	// stream is as this record is parsed.
	start := d.decoded + offset

	// Filters are applied in queue order, so a block starting before the last
	// one queued is malformed. Comparing absolute starts needs only the tail
	// entry; the relative encoding this replaced had to walk the whole queue.
	if n := len(d.fl); n > 0 && start < d.fl[n-1].start {
		return ErrInvalidFilter
	}

	fb := FilterBlock{
		start: start,
		// Safe on every platform: the bound above caps length at 4 MB.
		length: int(length),
		ftype:  uint8(ftype),
	}

	switch ftype {
	case 0:
		n, err := d.br.ReadBits(5)
		if err != nil {
			return err
		}
		fb.param = uint8(n + 1)
	case 1, 2, 3:
		// No extra parameters needed
	default:
		return ErrUnknownFilter
	}

	// A zero-length block transforms nothing. Dropping it here rather than at
	// dequeue keeps Read from returning (0, nil) against a non-empty buffer,
	// which would violate io.Reader.
	if fb.length == 0 {
		return nil
	}

	d.fl = append(d.fl, fb)
	return nil
}

func (d *decoder50) decodeLength(win *Window, i int) error {
	offset := d.offset[i]
	copy(d.offset[1:i+1], d.offset[:i])
	d.offset[0] = offset

	sl, err := d.lengthDecoder.ReadSym(d.br)
	if err != nil {
		return err
	}
	d.length, err = slotToLength(d.br, sl)
	if err == nil {
		err = win.CopyBytes(d.length, d.offset[0])
	}
	if err == nil {
		d.decoded += int64(d.length)
	}
	return err
}

func (d *decoder50) decodeOffset(win *Window, i int) error {
	length, err := slotToLength(d.br, i)
	if err != nil {
		return err
	}

	offset := 1
	slot, err := d.offsetDecoder.ReadSym(d.br)
	if err != nil {
		return err
	}
	if slot < 4 {
		offset += slot
	} else {
		bitCount := uint8(slot/2 - 1)
		offset += (2 | (slot & 1)) << bitCount

		if bitCount >= 4 {
			bitCount -= 4
			if bitCount > 0 {
				n, err := d.br.ReadBits(bitCount)
				if err != nil {
					return err
				}
				offset += n << 4
			}
			n, err := d.lowoffsetDecoder.ReadSym(d.br)
			if err != nil {
				return err
			}
			offset += n
		} else {
			n, err := d.br.ReadBits(bitCount)
			if err != nil {
				return err
			}
			offset += n
		}
	}
	if offset > 0x100 {
		length++
		if offset > 0x2000 {
			length++
			if offset > 0x40000 {
				length++
			}
		}
	}
	d.offset[3] = d.offset[2]
	d.offset[2] = d.offset[1]
	d.offset[1] = d.offset[0]
	d.offset[0] = offset
	d.length = length
	if err := win.CopyBytes(d.length, d.offset[0]); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// decodeSymbol maps a decoded symbol to its sliding window or filter action.
func (d *decoder50) decodeSymbol(win *Window, sym int) error {
	switch {
	case sym < 256:
		win.writeByte(byte(sym))
		d.decoded++
		return nil
	case sym >= 262:
		return d.decodeOffset(win, sym-262)
	case sym >= 258:
		return d.decodeLength(win, sym-258)
	case sym == 257:
		if err := win.CopyBytes(d.length, d.offset[0]); err != nil {
			return err
		}
		d.decoded += int64(d.length)
		return nil
	default: // sym == 256:
		return d.readFilter(win)
	}
}

// fill decodes LZ literals and back-references into the circular window.
func (d *decoder50) fill(win *Window) error {
	for win.Available() < win.size/2 {
		if d.br == nil {
			if err := d.readBlockHeader(); err != nil {
				return err
			}
		}
		sym, err := d.mainDecoder.ReadSym(d.br)
		if err != nil {
			if err == io.EOF {
				if d.lastBlock {
					return io.EOF
				}
				d.br = nil
				continue
			}
			return err
		}

		if err = d.decodeSymbol(win, sym); err != nil {
			if err == io.EOF {
				return ErrDecoderOutOfData
			}
			return err
		}
	}
	return nil
}

// stageFilterInput fills buf with a filter block's input, decoding more data
// when the window holds less than the block needs.
//
// Draining must precede decoding: fill returns as soon as the window is half
// full, so waiting for the whole block to become available before draining
// would never make progress for a block larger than half the window. Each
// iteration either copies at least one byte or leaves the decoder having
// produced at least one, so the loop is bounded without a retry counter.
//
// A block the stream cannot satisfy yields io.ErrUnexpectedEOF. io.EOF must not
// escape here: the caller would read it as a clean end of file and silently
// truncate the output.
func (d *decoder50) stageFilterInput(win *Window, buf []byte) error {
	for got := 0; got < len(buf); {
		n, _ := win.Read(buf[got:])
		got += n
		if got == len(buf) {
			return nil
		}

		err := d.fill(win)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrDecoderOutOfData) {
			return err
		}
		if n == 0 && win.Available() == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// Read decompresses the stream into p, reading directly from the sliding window
// when no filter is pending to avoid intermediate staging allocations.
func (d *decoder50) Read(win *Window, p []byte) (int, error) {
	// Drain any leftover filter output from a previous call first.
	if len(d.outbuf) > 0 {
		n := copy(p, d.outbuf)
		d.outbuf = d.outbuf[n:]
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Ensure the window has decoded data ready.
	if win.Available() == 0 {
		err := d.fill(win)
		if err != nil && !errors.Is(err, ErrDecoderOutOfData) && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if win.Available() == 0 {
			return 0, io.EOF
		}
	}

	// Fast path: no filter queued — copy window → p directly. Window.Read
	// returns at most len(p) bytes; the caller drives further progress.
	if len(d.fl) == 0 {
		n, _ := win.Read(p)
		d.tot += int64(n)
		return n, nil
	}

	// A filter is pending. Emit anything ahead of it first. The gap is derived
	// from tot on each call rather than carried in the queue entry, so there is
	// no per-filter counter to keep in step.
	head := &d.fl[0]
	if gap := head.start - d.tot; gap > 0 {
		limit := min(int(gap), win.Available(), len(p))
		n, _ := win.Read(p[:limit])
		d.tot += int64(n)
		return n, nil
	}

	// Apply the filter. f is a copy because d.fl is resliced immediately below,
	// and staging can drive a fill that appends to d.fl and reallocates it.
	//
	// Reuse filterBuf for the input. Note: some filter implementations return a
	// slice aliasing their input, so filterBuf must stay stable until outbuf
	// drains. That's guaranteed because Read only reaches this branch when
	// outbuf is empty.
	f := *head
	// Shift down rather than resliceing forward. Reslicing would advance the
	// base pointer and shrink capacity permanently, since init restores the
	// length but not the original array, so a long-lived decoder would
	// eventually exhaust the preallocation and append inside Read.
	copy(d.fl, d.fl[1:])
	d.fl = d.fl[:len(d.fl)-1]
	if cap(d.filterBuf) < f.length {
		d.filterBuf = make([]byte, f.length)
	} else {
		d.filterBuf = d.filterBuf[:f.length]
	}
	if err := d.stageFilterInput(win, d.filterBuf); err != nil {
		return 0, err
	}

	// A filter overlapping this block would have to be applied to this block's
	// output rather than to fresh window data. unrar supports that for blocks
	// sharing a start and length exactly; this rejects it, which no archive
	// from a current encoder should hit.
	if len(d.fl) > 0 && d.fl[0].start < f.start+int64(f.length) {
		return 0, ErrInvalidFilter
	}

	var out []byte
	switch f.ftype {
	case 0:
		if cap(d.filterOutBuf) < f.length {
			d.filterOutBuf = make([]byte, f.length)
		} else {
			d.filterOutBuf = d.filterOutBuf[:f.length]
		}
		out = FilterDelta(int(f.param), d.filterBuf, d.filterOutBuf)
	case 1:
		out = FilterE8(0xe8, true, d.filterBuf, d.tot)
	case 2:
		out = FilterE8(0xe9, true, d.filterBuf, d.tot)
	case 3:
		out = FilterArm(d.filterBuf, d.tot)
	default:
		// readFilter rejects unknown types before queueing, so this is
		// unreachable. Erroring rather than falling through keeps a future
		// filter type from leaving out nil, which would return no bytes and no
		// error against a non-empty buffer.
		return 0, ErrUnknownFilter
	}

	d.tot += int64(len(out))
	n := copy(p, out)
	if n < len(out) {
		d.outbuf = out[n:]
	}
	return n, nil
}
