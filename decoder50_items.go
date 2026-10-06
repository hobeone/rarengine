package rarengine

import "io"

// tableSet is the four Huffman tables a block is decoded with. Tables are
// sequential state: a block without the new-tables flag uses the tables of
// the block before it, so whoever reads block headers in order owns the
// current set and hands each block a reference to the set in force.
type tableSet struct {
	main, offset, lowoffset, length huffmanDecoder
}

// prewarm sizes each table's symbol slice for its alphabet, so that load
// never allocates afterwards. An all-zero code-length table is a valid
// (empty) tree for Init.
func (ts *tableSet) prewarm() {
	var zero [tableSize5]byte
	_ = ts.load(zero[:])
}

// load initialises the four tables from one tableSize5-byte code-length
// table, in the order the block header stores them.
func (ts *tableSet) load(cl []byte) error {
	if err := ts.main.Init(cl[:mainSize5]); err != nil {
		return err
	}
	cl = cl[mainSize5:]
	if err := ts.offset.Init(cl[:offsetSize5]); err != nil {
		return err
	}
	cl = cl[offsetSize5:]
	if err := ts.lowoffset.Init(cl[:lowoffsetSize5]); err != nil {
		return err
	}
	cl = cl[lowoffsetSize5:]
	return ts.length.Init(cl)
}

// copyFrom makes ts hold the same tables as src with its own symbol slice
// storage. huffmanDecoder.Init clears and refills the symbol slice in
// place, so two sets sharing one slice would corrupt each other on the
// next load; the arrays inside huffmanDecoder copy by value and need
// nothing more.
func (ts *tableSet) copyFrom(src *tableSet) {
	copyDecoder := func(dst, s *huffmanDecoder) {
		sym := dst.symbol
		*dst = *s
		if cap(sym) >= len(s.symbol) {
			sym = sym[:len(s.symbol)]
		} else {
			sym = make([]uint16, len(s.symbol))
		}
		copy(sym, s.symbol)
		dst.symbol = sym
	}
	copyDecoder(&ts.main, &src.main)
	copyDecoder(&ts.offset, &src.offset)
	copyDecoder(&ts.lowoffset, &src.lowoffset)
	copyDecoder(&ts.length, &src.length)
}

// decodeOffsetBits reads a match whose main symbol was 262+slot: the length
// from the slot and its extra bits, the distance from the offset tables,
// then the distance-dependent length adjustment. It touches no decoder
// state and no window, so it can run anywhere the block's bits and tables
// are.
func decodeOffsetBits(br *bitReader, ts *tableSet, slot int) (length, distance int, err error) {
	length, err = slotToLength(br, slot)
	if err != nil {
		return 0, 0, err
	}
	distance = 1
	oslot, err := ts.offset.ReadSym(br)
	if err != nil {
		return 0, 0, err
	}
	if oslot < 4 {
		distance += oslot
	} else {
		bitCount := uint8(oslot/2 - 1)
		distance += (2 | (oslot & 1)) << bitCount
		if bitCount >= 4 {
			bitCount -= 4
			if bitCount > 0 {
				n, err := br.ReadBits(bitCount)
				if err != nil {
					return 0, 0, err
				}
				distance += n << 4
			}
			n, err := ts.lowoffset.ReadSym(br)
			if err != nil {
				return 0, 0, err
			}
			distance += n
		} else {
			n, err := br.ReadBits(bitCount)
			if err != nil {
				return 0, 0, err
			}
			distance += n
		}
	}
	if distance > 0x100 {
		length++
		if distance > 0x2000 {
			length++
			if distance > 0x40000 {
				length++
			}
		}
	}
	return length, distance, nil
}

// decodeLengthBits reads the length that follows a repeat-distance symbol
// (258..261).
func decodeLengthBits(br *bitReader, ts *tableSet) (int, error) {
	sl, err := ts.length.ReadSym(br)
	if err != nil {
		return 0, err
	}
	return slotToLength(br, sl)
}

// readFilterBits reads a filter record's fields. The bounds and the start
// position depend on the window and on how much has been decoded, so they
// are left to queueFilter.
func readFilterBits(br *bitReader) (offset, length int64, ftype, param uint8, err error) {
	offset, err = readFilter5Data(br)
	if err != nil {
		return
	}
	length, err = readFilter5Data(br)
	if err != nil {
		return
	}
	t, err := br.ReadBits(3)
	if err != nil {
		return
	}
	ftype = uint8(t)
	if ftype == 0 {
		n, rerr := br.ReadBits(5)
		if rerr != nil {
			err = rerr
			return
		}
		param = uint8(n + 1)
	}
	return
}

// applyMatch records a new (length, distance) pair as the most recent and
// copies it. The distance history rotates by one, as unrar's does.
func (d *decoder50) applyMatch(win *window, length, distance int) error {
	d.offset[3] = d.offset[2]
	d.offset[2] = d.offset[1]
	d.offset[1] = d.offset[0]
	d.offset[0] = distance
	d.length = length
	if err := d.copyMatch(win); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// applyRepDist reuses the distance slot positions back in the history,
// moving it to the front, with a freshly read length.
func (d *decoder50) applyRepDist(win *window, slot, length int) error {
	distance := d.offset[slot]
	copy(d.offset[1:slot+1], d.offset[:slot])
	d.offset[0] = distance
	d.length = length
	if err := d.copyMatch(win); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// applyRepLast repeats the last match exactly.
func (d *decoder50) applyRepLast(win *window) error {
	if err := d.copyMatch(win); err != nil {
		return err
	}
	d.decoded += int64(d.length)
	return nil
}

// queueFilter validates a filter record against the window and the decode
// position and queues it. This is the half of the old readFilter that needs
// the window; readFilterBits is the other half.
func (d *decoder50) queueFilter(win *window, offset, length int64, ftype, param uint8) error {
	if len(d.fl) >= maxQueuedFilters {
		return ErrTooManyFilters
	}
	// Bound both stream-supplied values, which reach 0xFFFFFFFF. A filter is
	// announced while the decoder is near its position, so an offset beyond
	// one window is malformed rather than merely distant. Both are
	// non-negative by construction, so an upper bound is the whole check.
	if length > maxFilterBlockSize || offset > int64(win.size) {
		return ErrInvalidFilter
	}
	// The filter starts offset bytes past the decode head, which is where
	// the stream is as this record is parsed.
	start := d.decoded + offset
	// Filters are applied in queue order, so a block starting before the
	// last one queued is malformed.
	if n := len(d.fl); n > 0 && start < d.fl[n-1].start {
		return ErrInvalidFilter
	}
	if ftype > 3 {
		return ErrUnknownFilter
	}
	// A zero-length block transforms nothing. Dropping it here rather than
	// at dequeue keeps Read from returning (0, nil) against a non-empty
	// buffer, which would violate io.Reader.
	if length == 0 {
		return nil
	}
	d.fl = append(d.fl, filterBlock{
		start:  start,
		length: int(length), // bounded above at 4 MB, so exact on every platform
		ftype:  ftype,
		param:  param,
	})
	return nil
}

// itemKind says which apply function an item is replayed with.
type itemKind uint8

const (
	itemLiteral   itemKind = iota // value: the byte
	itemMatch                     // length, value: distance
	itemRepDist                   // aux: slot 0..3, length
	itemRepLast                   //
	itemFilter                    // aux: ftype, length: param, value: offset (raw, <= 0xFFFFFFFF)
	itemFilterLen                 // value: length (raw); always follows itemFilter
)

// item is one decoded symbol with everything the block's bits determined on
// their own. What depends on earlier output -- the distance history, the
// decode position a filter is relative to, the window's history bound -- is
// resolved when the item is replayed. 8 bytes: a distance fits uint32
// exactly (slot 63 with every extra bit set is 4294967295) and a length
// fits uint16 (slot 43 is 3586 before the at most +3 adjustment).
type item struct {
	kind   itemKind
	aux    uint8
	length uint16
	value  uint32
}

const (
	// itemCap is a job's item array size: twice rar's 16384 symbols per
	// block, so a filter's two items and any encoder that packs more never
	// overflow in practice; the overflow path exists for the format's
	// 16 MiB blocks and for hostile input.
	itemCap = 32768
)

// blockJob is one block in flight: its bytes, the tables it decodes with,
// and what the worker produced.
type blockJob struct {
	payload   []byte
	bits      int
	lastBlock bool
	tables    *tableSet

	items   []item // len itemCap, filled to n
	n       int
	partial bool      // items filled before the block ended; resume holds the position
	resume  bitReader // the reader state at the first undecoded symbol
	err     error     // the error that ended decoding, nil at a clean block end

	oversize bool // payload is the serial buffer; the block is finished inline
	waited   bool // done has been received for this use of the slot

	done chan struct{} // buffered 1; the worker sends when the job is complete
}

// decodeBlockItems turns j's bits into items. It is the worker's whole job
// and touches nothing but j and j.tables (read-only). It starts at j.resume
// when that reader has a buffer (the dispatcher leaves it positioned after
// the block's tables) and at the payload's first bit otherwise. A clean
// block end is j.err == nil; an error that ended the block is recorded as
// the serial path would have reported it from fill. If the items fill up
// first, j.partial is set and j.resume is left at the first undecoded
// symbol.
func decodeBlockItems(j *blockJob) {
	br := &j.resume
	if br.buf == nil {
		br.Reset(j.payload, j.bits)
	}
	ts := j.tables
	j.n = 0
	j.partial = false
	j.err = nil
	for {
		if j.n >= len(j.items)-1 { // a filter needs two slots
			j.partial = true
			return
		}
		sym, err := ts.main.ReadSym(br)
		if err != nil {
			if err == io.EOF {
				return
			}
			j.err = err
			return
		}
		it := &j.items[j.n]
		switch {
		case sym < 256:
			*it = item{kind: itemLiteral, value: uint32(sym)}
			j.n++
		case sym >= 262:
			length, distance, err := decodeOffsetBits(br, ts, sym-262)
			if err != nil {
				j.err = mapInnerErr(err)
				return
			}
			*it = item{kind: itemMatch, length: uint16(length), value: uint32(distance)}
			j.n++
		case sym >= 258:
			length, err := decodeLengthBits(br, ts)
			if err != nil {
				j.err = mapInnerErr(err)
				return
			}
			*it = item{kind: itemRepDist, aux: uint8(sym - 258), length: uint16(length)}
			j.n++
		case sym == 257:
			*it = item{kind: itemRepLast}
			j.n++
		default: // 256
			offset, length, ftype, param, err := readFilterBits(br)
			if err != nil {
				j.err = mapInnerErr(err)
				return
			}
			*it = item{kind: itemFilter, aux: ftype, length: uint16(param), value: uint32(offset)}
			j.items[j.n+1] = item{kind: itemFilterLen, value: uint32(length)}
			j.n += 2
		}
	}
}

// mapInnerErr is fill's mapping for an error from inside a symbol: running
// out of bits mid-symbol is ErrDecoderOutOfData, not a clean end.
func mapInnerErr(err error) error {
	if err == io.EOF {
		return ErrDecoderOutOfData
	}
	return err
}

// replayItems applies j.items[*idx:] to the window until the window stages
// target bytes or the items run out, advancing *idx. It is the serial
// loop's apply half, driven from the item array instead of from the bit
// reader. It returns true when the job's items are exhausted.
func (d *decoder50) replayItems(win *window, j *blockJob, idx *int, target int) (bool, error) {
	for *idx < j.n {
		if win.Available() >= target {
			return false, nil
		}
		it := j.items[*idx]
		*idx++
		var err error
		switch it.kind {
		case itemLiteral:
			win.writeByte(byte(it.value))
			d.decoded++
		case itemMatch:
			err = d.applyMatch(win, int(it.length), int(it.value))
		case itemRepDist:
			err = d.applyRepDist(win, int(it.aux), int(it.length))
		case itemRepLast:
			err = d.applyRepLast(win)
		case itemFilter:
			if len(d.fl) >= maxQueuedFilters {
				return false, ErrTooManyFilters
			}
			if *idx >= j.n || j.items[*idx].kind != itemFilterLen {
				return false, ErrCorruptDecodeHeader
			}
			ln := j.items[*idx]
			*idx++
			err = d.queueFilter(win, int64(it.value), int64(ln.value), it.aux, uint8(it.length))
		default:
			return false, ErrCorruptDecodeHeader
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// finishBlockInline continues a block the worker left partial. The serial
// code takes over from the saved reader position with the job's tables,
// and runs until the block ends or the window stages target bytes. While
// it runs, d.br is the live reader, so a caller that sees blockDone false
// must call again before touching any other block. It returns true when
// the block has ended.
func (d *decoder50) finishBlockInline(win *window, j *blockJob, target int) (blockDone bool, err error) {
	if d.br == nil {
		d.tables.copyFrom(j.tables)
		d.bitReader = j.resume
		d.br = &d.bitReader
		d.lastBlock = j.lastBlock
	}
	for win.Available() < target {
		sym, err := d.tables.main.ReadSym(d.br)
		if err != nil {
			if err == io.EOF {
				d.br = nil
				return true, nil
			}
			return true, err
		}
		if err := d.decodeSymbol(win, sym); err != nil {
			return true, mapInnerErr(err)
		}
	}
	return false, nil
}
