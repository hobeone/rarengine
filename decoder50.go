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
	filter func([]byte, int64) []byte
}

// decoder50 manages the LZ77 dynamic decompression state machine.
type decoder50 struct {
	r          io.Reader
	br         *BitReader
	codeLength [tableSize5]byte
	lastBlock  bool
	offsetSize int

	mainDecoder      HuffmanDecoder
	offsetDecoder    HuffmanDecoder
	lowoffsetDecoder HuffmanDecoder
	lengthDecoder    HuffmanDecoder

	offset [4]int
	length int

	fl     []*FilterBlock
	outbuf []byte // Buffered decompressed output bytes ready for consumption
	tot    int64  // Total number of bytes read/output so far
}

func newDecoder50() *decoder50 {
	return &decoder50{
		offsetSize: offsetSize5,
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
		d.fl = nil
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

	for i := byte(0); i < bytecount; i++ {
		n := blockBytesBuf[i]
		sum ^= n
		blockBytes |= int(n) << (i * 8)
	}

	if sum != hsum {
		return ErrCorruptDecodeHeader
	}

	blockBits += (blockBytes - 1) * 8

	payload := make([]byte, blockBytes)
	_, err = io.ReadFull(d.r, payload)
	if err != nil {
		return err
	}

	d.br = NewBitReader(payload, blockBits)
	d.lastBlock = flags&0x40 > 0

	if flags&0x80 > 0 {
		err = ReadCodeLengthTable(d.br, d.codeLength[:], false)
		if err != nil {
			return err
		}
		cl := d.codeLength[:]
		d.mainDecoder.Init(cl[:mainSize5])
		cl = cl[mainSize5:]
		d.offsetDecoder.Init(cl[:d.offsetSize])
		cl = cl[d.offsetSize:]
		d.lowoffsetDecoder.Init(cl[:lowoffsetSize5])
		cl = cl[lowoffsetSize5:]
		d.lengthDecoder.Init(cl)
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

	fb := new(FilterBlock)
	var err error

	fb.offset, err = readFilter5Data(d.br)
	if err != nil {
		return err
	}
	fb.length, err = readFilter5Data(d.br)
	if err != nil {
		return err
	}
	ftype, err := d.br.ReadBits(3)
	if err != nil {
		return err
	}

	fb.offset += win.w - win.r
	fb.offset %= win.size
	if fb.offset < 0 {
		fb.offset += win.size
	}
	fb.length %= win.size
	if fb.length < 0 {
		fb.length += win.size
	}

	switch ftype {
	case 0:
		n, err := d.br.ReadBits(5)
		if err != nil {
			return err
		}
		fb.filter = func(buf []byte, offset int64) []byte { return FilterDelta(n+1, buf) }
	case 1:
		fb.filter = func(buf []byte, offset int64) []byte { return FilterE8(0xe8, true, buf, offset) }
	case 2:
		fb.filter = func(buf []byte, offset int64) []byte { return FilterE8(0xe9, true, buf, offset) }
	case 3:
		fb.filter = FilterArm
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
	copy(d.offset[1:], d.offset[:])
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
				win.WriteByte(byte(sym))
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

// decode executes fill and process filters, populating outbuf with output bytes.
func (d *decoder50) decode(win *Window) error {
	if win.Available() == 0 {
		err := d.fill(win)
		if err != nil && !errors.Is(err, ErrDecoderOutOfData) && !errors.Is(err, io.EOF) {
			return err
		}
	}

	avail := win.Available()
	if avail == 0 {
		return io.EOF
	}

	if len(d.fl) == 0 {
		d.outbuf = make([]byte, avail)
		_, _ = win.Read(d.outbuf)
		d.tot += int64(len(d.outbuf))
		return nil
	}

	f := d.fl[0]
	if f.offset > 0 {
		n := f.offset
		if n > avail {
			n = avail
		}
		d.outbuf = make([]byte, n)
		_, _ = win.Read(d.outbuf)
		f.offset -= n
		d.tot += int64(n)
		return nil
	}

	d.fl = d.fl[1:]

	filterInput := make([]byte, f.length)
	_, _ = win.Read(filterInput)

	filterOutput := f.filter(filterInput, d.tot)
	d.outbuf = filterOutput
	d.tot += int64(len(filterOutput))
	return nil
}

// Read decompresses the stream sequentially into p.
func (d *decoder50) Read(win *Window, p []byte) (int, error) {
	if len(d.outbuf) == 0 {
		err := d.decode(win)
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, d.outbuf)
	d.outbuf = d.outbuf[n:]
	return n, nil
}
