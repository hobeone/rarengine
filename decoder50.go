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
)

// FilterBlock holds parameters for post-processing execution.
type FilterBlock struct {
	offset int
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

	fl        []FilterBlock
	outbuf    []byte // Leftover filter output that didn't fit in the caller's buffer
	filterBuf []byte // Reusable scratch for filter input; reused once outbuf drains
	tot       int64  // Total number of bytes read/output so far
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

func readFilter5Data(br *BitReader) (int, error) {
	bytesVal, err := br.ReadBits(2)
	if err != nil {
		return 0, err
	}
	bytesVal++

	var data int
	for i := 0; i < bytesVal; i++ {
		n, err := br.ReadBits(8)
		if err != nil {
			return 0, err
		}
		data |= n << (uint(i) * 8)
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

	offset += win.w - win.r
	offset %= win.size
	if offset < 0 {
		offset += win.size
	}
	length %= win.size
	if length < 0 {
		length += win.size
	}

	fb := FilterBlock{
		offset: offset,
		length: length,
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
	return win.CopyBytes(d.length, d.offset[0])
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
		if err == nil {
			switch {
			case sym < 256:
				win.writeByte(byte(sym))
			case sym >= 262:
				err = d.decodeOffset(win, sym-262)
			case sym >= 258:
				err = d.decodeLength(win, sym-258)
			case sym == 257:
				err = win.CopyBytes(d.length, d.offset[0])
			default: // sym == 256:
				err = d.readFilter(win)
			}
		} else if err == io.EOF {
			if d.lastBlock {
				return io.EOF
			}
			d.br = nil
			continue
		}
		if err != nil {
			if err == io.EOF {
				return ErrDecoderOutOfData
			}
			return err
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

	// A filter is pending. Drain its pre-filter passthrough first.
	f := d.fl[0]
	if f.offset > 0 {
		limit := min(f.offset, win.Available(), len(p))
		n, _ := win.Read(p[:limit])
		f.offset -= n
		d.tot += int64(n)
		return n, nil
	}

	// Apply the filter. Reuse filterBuf for the input. Note: some filter
	// implementations return a slice aliasing their input, so filterBuf must
	// stay stable until outbuf drains. That's guaranteed because Read only
	// reaches this branch when outbuf is empty.
	d.fl = d.fl[1:]
	if cap(d.filterBuf) < f.length {
		d.filterBuf = make([]byte, f.length)
	} else {
		d.filterBuf = d.filterBuf[:f.length]
	}
	_, _ = win.Read(d.filterBuf)

	var out []byte
	switch f.ftype {
	case 0:
		out = FilterDelta(int(f.param), d.filterBuf)
	case 1:
		out = FilterE8(0xe8, true, d.filterBuf, d.tot)
	case 2:
		out = FilterE8(0xe9, true, d.filterBuf, d.tot)
	case 3:
		out = FilterArm(d.filterBuf, d.tot)
	}

	d.tot += int64(len(out))
	n := copy(p, out)
	if n < len(out) {
		d.outbuf = out[n:]
	}
	return n, nil
}
