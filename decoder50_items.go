package rarengine

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
