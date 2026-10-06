package rarengine

import (
	"errors"
	"fmt"
	"io"
	"sync"
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

// filterBlock holds parameters for post-processing execution.
type filterBlock struct {
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
	br         *bitReader // points to bitReader when a block is loaded; nil between blocks
	bitReader  bitReader  // reusable bit reader (embedded to avoid per-block allocations)
	payloadBuf []byte     // reusable scratch buffer for compressed block payload
	codeLength [tableSize5]byte
	lastBlock  bool

	// dictSize is the dictionary size the member's header declares, for
	// classifying a refused match; see copyMatch. Set per member by
	// buildChain, never consulted to refuse anything. Zero (a decoder driven
	// directly) declares nothing, which classifies as corruption.
	dictSize int64

	tables tableSet
	// pipe is the block read-ahead, nil until a Reader asks for workers.
	// pipeMu and pipeStopped are the only decoder state Close touches from
	// another goroutine. pipe is written only under pipeMu (setPipeline) and
	// read under it by stopWorkers and restartWorkers; the traversal
	// goroutine, which is its only writer, may read it without the lock, as
	// fillParallel and the rest of the decode path do. pipeStopped latches a
	// Close until Reset, so one that lands before the first pipeline exists is
	// honoured when setPipeline publishes it.
	pipe          *blockPipeline
	pipeMu        sync.Mutex
	pipeStopped   bool
	bitlenDecoder huffmanDecoder // scratch for ReadCodeLengthTable
	headBuf       [5]byte        // scratch for readBlockHead; a local would escape through io.Reader

	offset [4]int
	length int

	fl           []filterBlock
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
	d := &decoder50{
		fl: make([]filterBlock, 0, maxQueuedFilters),
	}
	d.tables.prewarm()
	return d
}

// init prepares the decoder state.
func (d *decoder50) init(r io.Reader, reset bool) {
	d.r = r
	d.lastBlock = false
	// Pointing the decoder at a new reader invalidates whatever bits the last
	// one left buffered. A member larger than the fill target is not decoded
	// to the end of its block before the caller can abandon it, so d.br
	// survives non-nil, and fill() reads d.br != nil as "still inside a
	// block" -- resuming the next member from the previous member's bits,
	// against the Huffman tables it left behind. It is not conditional on
	// reset: a new source always means the buffered bits belong to a stream
	// this decoder is no longer reading.
	d.br = nil
	if d.pipe != nil {
		d.pipe.drain()
	}
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
	h, err := readBlockHead(d.r, &d.headBuf)
	if err != nil {
		return err
	}
	if cap(d.payloadBuf) < h.blockBytes {
		d.payloadBuf = make([]byte, h.blockBytes)
	} else {
		d.payloadBuf = d.payloadBuf[:h.blockBytes]
	}
	if _, err = io.ReadFull(d.r, d.payloadBuf); err != nil {
		return err
	}
	d.bitReader.Reset(d.payloadBuf, h.blockBits)
	d.br = &d.bitReader
	d.lastBlock = h.lastBlock
	if h.newTables {
		if err = readCodeLengthTable(d.br, d.codeLength[:], &d.bitlenDecoder); err != nil {
			return err
		}
		if err = d.tables.load(d.codeLength[:]); err != nil {
			return err
		}
	}
	return nil
}

func slotToLength(br *bitReader, n int) (int, error) {
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
func readFilter5Data(br *bitReader) (int64, error) {
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

func (d *decoder50) readFilter(win *window) error {
	// The record is read before the queue is checked, as a worker reads it
	// before replay does: truncated bits then report out-of-data on both paths
	// even when the queue is full. The queue is checked only after, in
	// queueFilter (replay also checks it before pairing a filter's items).
	offset, length, ftype, param, err := readFilterBits(d.br)
	if err != nil {
		return err
	}
	return d.queueFilter(win, offset, length, ftype, param)
}

func (d *decoder50) decodeLength(win *window, slot int) error {
	length, err := decodeLengthBits(d.br, &d.tables)
	if err != nil {
		return err
	}
	return d.applyRepDist(win, slot, length)
}

func (d *decoder50) decodeOffset(win *window, slot int) error {
	length, distance, err := decodeOffsetBits(d.br, &d.tables, slot)
	if err != nil {
		return err
	}
	return d.applyMatch(win, length, distance)
}

// copyMatch performs the match the decoder's current length and offset[0]
// describe, and classifies a refusal.
//
// window.CopyBytes decides WHETHER the copy happens and is not touched by the
// classification: this only chooses which error a refusal is reported as. A
// refused copy moves nothing, so the window's state afterwards is the state
// the refusal was decided on, and the classification reads it from there.
//
// A refusal is a capacity limit, ErrDictionaryTooLarge, only when all four
// hold:
//
//   - the history already spans the whole window. A stream cannot legitimately
//     reference bytes its file has not produced, whatever dictionary the
//     header declares, so a short history is corruption.
//   - the distance exceeds the window. With full history that is exactly what
//     CopyBytes refused it for.
//   - the header declared a dictionary larger than the window. One that
//     fits was exceeded by the stream itself, which is corruption.
//   - the distance fits inside that declared dictionary. One beyond it
//     contradicts the header the stream arrived with, so no larger window
//     would have made it valid: that is corruption too.
//
// Anything else keeps ErrWindowOffsetBounds alone. The capacity case wraps
// both, so errors.Is(err, ErrWindowOffsetBounds) stays true for everything
// that matched it before.
func (d *decoder50) copyMatch(win *window) error {
	err := win.CopyBytes(d.length, d.offset[0])
	if err == nil {
		return nil
	}
	if win.historyLen() == win.size && d.offset[0] > win.size &&
		d.dictSize > int64(win.size) && int64(d.offset[0]) <= d.dictSize {
		return fmt.Errorf("%w: stream references %d bytes back but the window holds %d and the header declares a %d-byte dictionary: %w",
			ErrDictionaryTooLarge, d.offset[0], win.size, d.dictSize, err)
	}
	return err
}

// decodeSymbol maps a decoded symbol to its sliding window or filter action.
func (d *decoder50) decodeSymbol(win *window, sym int) error {
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
		return d.applyRepLast(win)
	default: // sym == 256:
		return d.readFilter(win)
	}
}

// fill decodes LZ literals and back-references into the circular window,
// stopping once the window stages fillTarget bytes of unread output; see
// window.fillTarget for why that is not simply half the window.
func (d *decoder50) fill(win *window) error {
	if d.pipe != nil && d.pipe.engaged {
		return d.fillParallel(win)
	}
	target := win.fillTarget()
	for win.Available() < target {
		if d.br == nil {
			if err := d.readBlockHeader(); err != nil {
				return err
			}
		}
		sym, err := d.tables.main.ReadSym(d.br)
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
			return mapInnerErr(err)
		}
	}
	return nil
}

// stageFilterInput fills buf with a filter block's input, decoding more data
// when the window holds less than the block needs.
//
// Draining must precede decoding: fill returns as soon as the window stages
// its fill target, so waiting for the whole block to become available before
// draining would never make progress for a block larger than that. Each
// iteration either copies at least one byte or leaves the decoder having
// produced at least one, so the loop is bounded without a retry counter.
//
// A block the stream cannot satisfy yields io.ErrUnexpectedEOF. io.EOF must not
// escape here: the caller would read it as a clean end of file and silently
// truncate the output.
func (d *decoder50) stageFilterInput(win *window, buf []byte) error {
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
func (d *decoder50) Read(win *window, p []byte) (int, error) {
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

	// Fast path: no filter queued — copy window → p directly. window.Read
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
		out = filterDelta(int(f.param), d.filterBuf, d.filterOutBuf)
	case 1:
		out = filterE8(0xe8, d.filterBuf, d.tot)
	case 2:
		out = filterE8(0xe9, d.filterBuf, d.tot)
	case 3:
		out = filterArm(d.filterBuf, d.tot)
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
