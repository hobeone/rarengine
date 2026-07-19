package rarengine

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidRAR3Block = errors.New("rarengine: invalid rar3 block header")
	ErrPPMUnsupported   = errors.New("rarengine: rar3 ppmd compression not implemented")
)

const (
	nc30  = 299 // Main table size
	dc30  = 60  // Distance table size
	ldc30 = 17  // Low distance table size
	rc30  = 28  // Length table size
	bc30  = 20  // Bit length table size

	huffTableSize30 = nc30 + dc30 + ldc30 + rc30 // 404
)

var ldecode30 = [28]int{
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 10, 12, 14, 16, 20, 24, 28,
	32, 40, 48, 56, 64, 80, 96, 112,
	128, 160, 192, 224,
}

var lbits30 = [28]uint8{
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4,
	5, 5, 5, 5,
}

var sddecode30 = [8]int{0, 4, 8, 16, 32, 64, 128, 192}
var sdbits30 = [8]uint8{2, 2, 3, 4, 5, 6, 6, 6}

var dbits30 [60]uint8
var ddecode30 [60]int

func init() {
	// Initialize DDecode and DBits lookup tables for RAR3
	dist := 0
	bit := 0
	for i := range 60 {
		if i < 4 {
			dbits30[i] = 0
			ddecode30[i] = dist
			dist++
		} else if i < 34 {
			if (i & 1) == 0 {
				bit++
			}
			dbits30[i] = uint8(bit)
			ddecode30[i] = dist
			dist += 1 << bit
		} else if i < 48 {
			dbits30[i] = 16
			ddecode30[i] = dist
			dist += 1 << 16
		} else {
			dbits30[i] = 18
			ddecode30[i] = dist
			dist += 1 << 18
		}
	}
}

type rar3Decoder struct {
	r              io.Reader
	unpackedSize   int64
	written        int64
	win            *Window
	br             BitReader
	inBuf          []byte
	mainDecoder    HuffmanDecoder
	distDecoder    HuffmanDecoder
	lowDistDecoder HuffmanDecoder
	lengthDecoder  HuffmanDecoder
	levelDecoder   HuffmanDecoder

	oldDist         [4]int
	lastLength      int
	lowDistRepCount int
	prevLowDist     int
	lastLevels      [huffTableSize30]byte
	tablesRead      bool
	isPPM           bool
	eof             bool
	readErr         error
}

func newRAR3Decoder(win *Window) *rar3Decoder {
	return &rar3Decoder{
		win:   win,
		inBuf: make([]byte, 64*1024),
	}
}

func (d *rar3Decoder) Reset(r io.Reader, unpackedSize int64, solid bool) {
	d.r = r
	d.unpackedSize = unpackedSize
	d.written = 0
	d.tablesRead = false
	d.isPPM = false
	d.eof = false
	d.readErr = nil
	if !solid {
		d.oldDist = [4]int{0, 0, 0, 0}
		d.lastLength = 0
		d.lowDistRepCount = 0
		d.prevLowDist = 0
		clear(d.lastLevels[:])
	}
}

func (d *rar3Decoder) refillBitReader() error {
	n, err := io.ReadFull(d.r, d.inBuf)
	if n > 0 {
		d.br.Reset(d.inBuf[:n], n*8)
		return nil
	}
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			d.eof = true
			return io.EOF
		}
		return err
	}
	return nil
}

func (d *rar3Decoder) readBlockHeader() error {
	// 1. Align byte boundary
	d.br.AlignByte()

	// 2. Read 1st bit: block mode (0=LZ, 1=PPMd)
	modeBit, err := d.br.ReadBits(1)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, ErrDecoderOutOfData) {
			if refillErr := d.refillBitReader(); refillErr != nil {
				return refillErr
			}
			modeBit, err = d.br.ReadBits(1)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if modeBit != 0 {
		d.isPPM = true
		return ErrPPMUnsupported
	}
	d.isPPM = false

	// 3. Read 2nd bit: table reuse flag (0=fresh/reset, 1=keep/delta)
	reuseBit, err := d.br.ReadBits(1)
	if err != nil {
		return err
	}

	if reuseBit == 0 {
		clear(d.lastLevels[:])
	}

	// 4. Decode 20 bit-length levels (BC30 = 20)
	var bitlength [bc30]byte
	for i := 0; i < bc30; i++ {
		length, err := d.br.ReadBits(4)
		if err != nil {
			return err
		}
		if length == 15 {
			zeroCount, err := d.br.ReadBits(4)
			if err != nil {
				return err
			}
			if zeroCount != 0 {
				zeroCount += 2
				for zeroCount > 0 && i < bc30 {
					bitlength[i] = 0
					zeroCount--
					i++
				}
				i--
				continue
			}
		}
		bitlength[i] = byte(length)
	}

	if err := d.levelDecoder.Init(bitlength[:]); err != nil {
		return err
	}

	// 5. Decode 404 table levels using levelDecoder
	var tableLevels [huffTableSize30]byte
	for i := 0; i < huffTableSize30; {
		sym, err := d.levelDecoder.ReadSym(&d.br)
		if err != nil {
			return err
		}
		if sym < 16 {
			tableLevels[i] = byte((sym + int(d.lastLevels[i])) & 0xF)
			i++
		} else if sym == 16 {
			count, err := d.br.ReadBits(3)
			if err != nil {
				return err
			}
			count += 3
			if i == 0 {
				return ErrInvalidRAR3Block
			}
			val := tableLevels[i-1]
			for count > 0 && i < huffTableSize30 {
				tableLevels[i] = val
				count--
				i++
			}
		} else if sym == 17 {
			count, err := d.br.ReadBits(3)
			if err != nil {
				return err
			}
			count += 3
			for count > 0 && i < huffTableSize30 {
				tableLevels[i] = 0
				count--
				i++
			}
		} else if sym == 18 {
			count, err := d.br.ReadBits(7)
			if err != nil {
				return err
			}
			count += 11
			for count > 0 && i < huffTableSize30 {
				tableLevels[i] = 0
				count--
				i++
			}
		}
	}

	copy(d.lastLevels[:], tableLevels[:])
	d.tablesRead = true

	// Partition the 404 levels into 4 Huffman decoders:
	// Main (299), Distance (60), LowDistance (17), Length (28)
	if err := d.mainDecoder.Init(tableLevels[0:nc30]); err != nil {
		return err
	}
	if err := d.distDecoder.Init(tableLevels[nc30 : nc30+dc30]); err != nil {
		return err
	}
	if err := d.lowDistDecoder.Init(tableLevels[nc30+dc30 : nc30+dc30+ldc30]); err != nil {
		return err
	}
	if err := d.lengthDecoder.Init(tableLevels[nc30+dc30+ldc30 : huffTableSize30]); err != nil {
		return err
	}

	return nil
}

func (d *rar3Decoder) decodeDistance(slot int) (int, error) {
	if slot < 4 {
		return slot, nil
	}
	bits := dbits30[slot]
	dist := ddecode30[slot]

	if bits > 0 {
		if bits >= 4 {
			if bits > 4 {
				addBits, err := d.br.ReadBits(bits - 4)
				if err != nil {
					return 0, err
				}
				dist += addBits << 4
			}
			if d.lowDistRepCount > 0 {
				d.lowDistRepCount--
				dist += d.prevLowDist
			} else {
				lowSym, err := d.lowDistDecoder.ReadSym(&d.br)
				if err != nil {
					return 0, err
				}
				if lowSym == 16 {
					d.lowDistRepCount = 15
					dist += d.prevLowDist
				} else {
					d.prevLowDist = lowSym
					dist += lowSym
				}
			}
		} else {
			addBits, err := d.br.ReadBits(bits)
			if err != nil {
				return 0, err
			}
			dist += addBits
		}
	}
	return dist, nil
}

func (d *rar3Decoder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if d.written >= d.unpackedSize {
		return 0, io.EOF
	}

	// First, drain any unread decompressed bytes from sliding window
	if d.win.Available() > 0 {
		n, _ := d.win.Read(p)
		d.written += int64(n)
		return n, nil
	}

	// Decompress into window until we produce output or hit EOF
	for d.written < d.unpackedSize {
		if !d.tablesRead {
			if err := d.readBlockHeader(); err != nil {
				return 0, err
			}
		}

		sym, err := d.mainDecoder.ReadSym(&d.br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrDecoderOutOfData) {
				if refillErr := d.refillBitReader(); refillErr != nil {
					if errors.Is(refillErr, io.EOF) && d.win.Available() > 0 {
						n, _ := d.win.Read(p)
						d.written += int64(n)
						return n, nil
					}
					return 0, refillErr
				}
				sym, err = d.mainDecoder.ReadSym(&d.br)
				if err != nil {
					return 0, err
				}
			} else {
				return 0, err
			}
		}

		if sym < 256 {
			// Literal byte
			d.win.writeByte(byte(sym))
			if d.win.Available() >= len(p) || d.win.Available() >= 32768 {
				n, _ := d.win.Read(p)
				d.written += int64(n)
				return n, nil
			}
			continue
		}

		if sym == 256 {
			// End of block / read new table header
			d.tablesRead = false
			continue
		}

		if sym == 257 || sym == 258 {
			// VM Filter Code/Data (unsupported in this baseline pass)
			return 0, fmt.Errorf("rarengine: rar3 filter VM symbol %d not supported", sym)
		}

		if sym >= 259 && sym <= 262 {
			// Repeat match distance R0..R3
			repIndex := sym - 259
			dist := d.oldDist[repIndex]

			// MTF update
			switch repIndex {
			case 1:
				d.oldDist[0], d.oldDist[1] = d.oldDist[1], d.oldDist[0]
			case 2:
				d.oldDist[0], d.oldDist[1], d.oldDist[2] = d.oldDist[2], d.oldDist[0], d.oldDist[1]
			case 3:
				d.oldDist[0], d.oldDist[1], d.oldDist[2], d.oldDist[3] = d.oldDist[3], d.oldDist[0], d.oldDist[1], d.oldDist[2]
			}

			lenSym, err := d.lengthDecoder.ReadSym(&d.br)
			if err != nil {
				return 0, err
			}
			matchLen := ldecode30[lenSym] + 2
			if lbits30[lenSym] > 0 {
				addBits, err := d.br.ReadBits(lbits30[lenSym])
				if err != nil {
					return 0, err
				}
				matchLen += addBits
			}
			d.lastLength = matchLen
			if err := d.win.CopyBytes(matchLen, dist+1); err != nil {
				return 0, err
			}
			if d.win.Available() >= len(p) || d.win.Available() >= 32768 {
				n, _ := d.win.Read(p)
				d.written += int64(n)
				return n, nil
			}
			continue
		}

		if sym >= 263 && sym <= 270 {
			// Short distance (length-2) match
			sdCode := sym - 263
			dist := sddecode30[sdCode]
			if sdbits30[sdCode] > 0 {
				addBits, err := d.br.ReadBits(sdbits30[sdCode])
				if err != nil {
					return 0, err
				}
				dist += addBits
			}

			// Shift MTF queue
			d.oldDist[3] = d.oldDist[2]
			d.oldDist[2] = d.oldDist[1]
			d.oldDist[1] = d.oldDist[0]
			d.oldDist[0] = dist

			d.lastLength = 2
			if err := d.win.CopyBytes(2, dist+1); err != nil {
				return 0, err
			}
			if d.win.Available() >= len(p) || d.win.Available() >= 32768 {
				n, _ := d.win.Read(p)
				d.written += int64(n)
				return n, nil
			}
			continue
		}

		if sym >= 271 && sym <= 298 {
			// Standard match length (>=3)
			lenCode := sym - 271
			matchLen := ldecode30[lenCode] + 3
			if lbits30[lenCode] > 0 {
				addBits, err := d.br.ReadBits(lbits30[lenCode])
				if err != nil {
					return 0, err
				}
				matchLen += addBits
			}

			distSlot, err := d.distDecoder.ReadSym(&d.br)
			if err != nil {
				return 0, err
			}
			dist, err := d.decodeDistance(distSlot)
			if err != nil {
				return 0, err
			}

			// Shift MTF queue
			d.oldDist[3] = d.oldDist[2]
			d.oldDist[2] = d.oldDist[1]
			d.oldDist[1] = d.oldDist[0]
			d.oldDist[0] = dist

			d.lastLength = matchLen
			if err := d.win.CopyBytes(matchLen, dist+1); err != nil {
				return 0, err
			}
			if d.win.Available() >= len(p) || d.win.Available() >= 32768 {
				n, _ := d.win.Read(p)
				d.written += int64(n)
				return n, nil
			}
			continue
		}
	}

	if d.win.Available() > 0 {
		n, _ := d.win.Read(p)
		d.written += int64(n)
		return n, nil
	}

	return 0, io.EOF
}
