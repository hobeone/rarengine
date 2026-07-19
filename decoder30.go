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
	produced       int64 // Total bytes produced into sliding window for current file
	written        int64 // Total bytes read out by caller via Read(p)
	win            *Window
	br             BitReader
	inBuf          []byte // Reusable 64KB stream buffer
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
	solid           bool
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
	d.produced = 0
	d.written = 0
	d.tablesRead = false
	d.isPPM = false
	d.solid = solid

	// Clear bit reader; incremental refills via RefillBuffer handle streaming
	d.br.Reset(nil, 0)

	if !solid {
		d.oldDist = [4]int{0, 0, 0, 0}
		d.lastLength = 0
		d.lowDistRepCount = 0
		d.prevLowDist = 0
		clear(d.lastLevels[:])
	}
}

func (d *rar3Decoder) refillBitReader() error {
	n, err := d.r.Read(d.inBuf)
	if n > 0 {
		d.br.RefillBuffer(d.inBuf[:n], n*8)
		return nil
	}
	if err != nil {
		return err
	}
	return io.EOF
}

func (d *rar3Decoder) readBits(n uint8) (int, error) {
	val, err := d.br.ReadBits(n)
	if errors.Is(err, ErrDecoderOutOfData) || errors.Is(err, io.EOF) {
		if refillErr := d.refillBitReader(); refillErr != nil {
			return 0, refillErr
		}
		return d.br.ReadBits(n)
	}
	return val, err
}

func (d *rar3Decoder) readSym(h *HuffmanDecoder) (int, error) {
	sym, err := h.ReadSym(&d.br)
	if errors.Is(err, ErrDecoderOutOfData) || errors.Is(err, io.EOF) {
		if refillErr := d.refillBitReader(); refillErr != nil {
			return 0, refillErr
		}
		return h.ReadSym(&d.br)
	}
	return sym, err
}

func (d *rar3Decoder) readBlockHeader() error {
	// 1. Align byte boundary
	d.br.AlignByte()

	// 2. Read 1st bit: block mode (0=LZ, 1=PPMd)
	modeBit, err := d.readBits(1)
	if err != nil {
		return err
	}

	if modeBit != 0 {
		d.isPPM = true
		return ErrPPMUnsupported
	}
	d.isPPM = false

	// 3. Read 2nd bit: table reuse flag (0=fresh/reset, 1=keep/delta)
	reuseBit, err := d.readBits(1)
	if err != nil {
		return err
	}

	if reuseBit == 0 {
		clear(d.lastLevels[:])
	}

	// 4. Decode 20 bit-length levels (BC30 = 20)
	var bitlength [bc30]byte
	for i := 0; i < bc30; i++ {
		length, err := d.readBits(4)
		if err != nil {
			return err
		}
		if length == 15 {
			zeroCount, err := d.readBits(4)
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
		sym, err := d.readSym(&d.levelDecoder)
		if err != nil {
			return err
		}
		if sym < 16 {
			tableLevels[i] = byte((sym + int(d.lastLevels[i])) & 0xF)
			i++
		} else if sym == 16 {
			count, err := d.readBits(3)
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
			count, err := d.readBits(3)
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
			count, err := d.readBits(7)
			if err != nil {
				return err
			}
			count += 11
			for count > 0 && i < huffTableSize30 {
				tableLevels[i] = 0
				count--
				i++
			}
		} else {
			return ErrInvalidRAR3Block
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
	if slot < 0 || slot >= 60 {
		return 0, ErrInvalidRAR3Block
	}
	if slot < 4 {
		return slot, nil
	}
	bits := dbits30[slot]
	dist := ddecode30[slot]

	if bits > 0 {
		if bits >= 4 {
			if bits > 4 {
				addBits, err := d.readBits(bits - 4)
				if err != nil {
					return 0, err
				}
				dist += addBits << 4
			}
			if d.lowDistRepCount > 0 {
				d.lowDistRepCount--
				dist += d.prevLowDist
			} else {
				lowSym, err := d.readSym(&d.lowDistDecoder)
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
			addBits, err := d.readBits(bits)
			if err != nil {
				return 0, err
			}
			dist += addBits
		}
	}
	return dist, nil
}

func (d *rar3Decoder) writeByte(c byte) {
	d.win.writeByte(c)
	d.produced++
}

func (d *rar3Decoder) copyMatch(matchLen int, dist int) error {
	if !d.solid && dist > int(d.produced)+d.win.Available() {
		return ErrWindowOffsetBounds
	}
	if err := d.win.CopyBytes(matchLen, dist); err != nil {
		return err
	}
	d.produced += int64(matchLen)
	return nil
}

func (d *rar3Decoder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Decompress into window until we produce required unpacked bytes or hit EOF
	for d.produced < d.unpackedSize {
		if d.win.Available() >= len(p) || d.win.Available() >= 32768 {
			break
		}

		if !d.tablesRead {
			if err := d.readBlockHeader(); err != nil {
				if d.win.Available() > 0 {
					n, _ := d.win.Read(p)
					d.written += int64(n)
					return n, nil
				}
				return 0, err
			}
		}

		sym, err := d.readSym(&d.mainDecoder)
		if err != nil {
			if d.win.Available() > 0 {
				n, _ := d.win.Read(p)
				d.written += int64(n)
				return n, nil
			}
			return 0, err
		}

		if sym < 256 {
			// Literal byte
			d.writeByte(byte(sym))
			continue
		}

		if sym == 256 {
			// End of block / read new table header
			d.tablesRead = false
			continue
		}

		if sym == 257 {
			// VM Filter Code (unsupported in this baseline pass)
			return 0, fmt.Errorf("rarengine: rar3 filter VM symbol %d not supported", sym)
		}

		if sym == 258 {
			// Repeat last match length at distance R0
			if d.lastLength > 0 {
				if err := d.copyMatch(d.lastLength, d.oldDist[0]+1); err != nil {
					return 0, err
				}
			}
			continue
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

			lenSym, err := d.readSym(&d.lengthDecoder)
			if err != nil {
				return 0, err
			}
			matchLen := ldecode30[lenSym] + 2
			if lbits30[lenSym] > 0 {
				addBits, err := d.readBits(lbits30[lenSym])
				if err != nil {
					return 0, err
				}
				matchLen += addBits
			}
			d.lastLength = matchLen
			if err := d.copyMatch(matchLen, dist+1); err != nil {
				return 0, err
			}
			continue
		}

		if sym >= 263 && sym <= 270 {
			// Short distance (length-2) match
			sdCode := sym - 263
			dist := sddecode30[sdCode]
			if sdbits30[sdCode] > 0 {
				addBits, err := d.readBits(sdbits30[sdCode])
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
			if err := d.copyMatch(2, dist+1); err != nil {
				return 0, err
			}
			continue
		}

		if sym >= 271 && sym <= 298 {
			// Standard match length (>=3)
			lenCode := sym - 271
			matchLen := ldecode30[lenCode] + 3
			if lbits30[lenCode] > 0 {
				addBits, err := d.readBits(lbits30[lenCode])
				if err != nil {
					return 0, err
				}
				matchLen += addBits
			}

			distSlot, err := d.readSym(&d.distDecoder)
			if err != nil {
				return 0, err
			}
			dist, err := d.decodeDistance(distSlot)
			if err != nil {
				return 0, err
			}

			distance := dist + 1
			if distance >= 0x2000 {
				matchLen++
				if distance >= 0x40000 {
					matchLen++
				}
			}

			// Shift MTF queue
			d.oldDist[3] = d.oldDist[2]
			d.oldDist[2] = d.oldDist[1]
			d.oldDist[1] = d.oldDist[0]
			d.oldDist[0] = dist

			d.lastLength = matchLen
			if err := d.copyMatch(matchLen, distance); err != nil {
				return 0, err
			}
			continue
		}
	}

	if d.win.Available() > 0 {
		n, _ := d.win.Read(p)
		d.written += int64(n)
		return n, nil
	}

	if d.written >= d.unpackedSize {
		return 0, io.EOF
	}

	return 0, io.EOF
}
