package rarengine

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

// handBits builds a block payload MSB first, as bitReader reads it.
type handBits struct {
	buf []byte
	n   int
}

// put appends the low k bits of v, most significant first.
func (w *handBits) put(v uint64, k int) {
	for i := k - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.buf = append(w.buf, 0)
		}
		if v>>uint(i)&1 == 1 {
			w.buf[len(w.buf)-1] |= 0x80 >> uint(w.n%8)
		}
		w.n++
	}
}

// Codes of the hand-built main table: A is "0", B is "10", symbol 262 (a
// match with length slot 0) is "11".
func (w *handBits) a()     { w.put(0, 1) }
func (w *handBits) b()     { w.put(2, 2) }
func (w *handBits) match() { w.put(3, 2) }

// handBlock frames w's bits as one block without tables: flags, checksum,
// the payload byte count, the payload.
func handBlock(w *handBits, last bool) []byte {
	nb := len(w.buf)
	bc := 1
	for nb >= 1<<(8*bc) {
		bc++
	}
	flags := byte((w.n-1)%8) | byte(bc-1)<<3
	if last {
		flags |= 0x40
	}
	sum := 0x5a ^ flags
	hdr := []byte{flags, 0}
	for i := range bc {
		b := byte(nb >> (8 * i))
		sum ^= b
		hdr = append(hdr, b)
	}
	hdr[1] = sum
	return append(hdr, w.buf...)
}

// literalBlocks frames count A literals as blocks of at most per symbols,
// none of them last. per stays under itemCap, so a worker decodes each whole.
func literalBlocks(count, per int) []byte {
	var out []byte
	for count > 0 {
		k := min(count, per)
		var w handBits
		for range k {
			w.a()
		}
		out = append(out, handBlock(&w, false)...)
		count -= k
	}
	return out
}

// handTables is a code-length table for the hand-built blocks: the main
// table above, and in the offset and low-offset tables the one symbol given
// (code "0"), or nothing when it is negative.
func handTables(offsetSym, lowSym int) []byte {
	cl := make([]byte, tableSize5)
	cl['A'], cl['B'], cl[262] = 1, 2, 2
	if offsetSym >= 0 {
		cl[mainSize5+offsetSym] = 1
	}
	if lowSym >= 0 {
		cl[mainSize5+offsetSize5+lowSym] = 1
	}
	return cl
}

// decodeMode is how a hand-built stream is decoded.
type decodeMode struct {
	name    string
	workers int
	limit   int // parallelPayloadLimit; 0 sends every block inline
}

var handModes = []decodeMode{
	{"serial", 1, maxParallelPayload},
	{"worker", 2, maxParallelPayload},
	{"inline", 2, 0},
}

// decodeHand decodes data with tables cl through decoder50.Read in a
// minimum-size window, returning every byte delivered and the error that
// ended it (io.EOF at a clean end).
func decodeHand(t *testing.T, m decodeMode, cl, data []byte, dictSize int64) ([]byte, error) {
	t.Helper()
	saved := parallelPayloadLimit
	parallelPayloadLimit = m.limit
	defer func() { parallelPayloadLimit = saved }()

	d := newDecoder50()
	if err := d.tables.load(cl); err != nil {
		t.Fatal(err)
	}
	d.init(bytes.NewReader(data), true)
	d.dictSize = dictSize
	d.setPipeline(m.workers)
	defer d.stopWorkers()
	win := newWindow(minWindowSize)
	if err := win.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 64<<10)
	for range 10000 {
		n, err := d.Read(win, buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
	t.Fatal("Read never returned an error")
	return nil, nil
}

// compareModes decodes data in every mode and requires each to deliver the
// serial bytes and error. It returns the serial outcome for the caller's
// setup assertions.
func compareModes(t *testing.T, cl, data []byte, dictSize int64) ([]byte, error) {
	t.Helper()
	want, wantErr := decodeHand(t, handModes[0], cl, data, dictSize)
	for _, m := range handModes[1:] {
		got, err := decodeHand(t, m, cl, data, dictSize)
		if !bytes.Equal(got, want) || errText(err) != errText(wantErr) {
			t.Errorf("%s: %d bytes %q, then %v\nserial: %d bytes %q, then %v",
				m.name, len(got), clip(got), err, len(want), clip(want), wantErr)
		}
	}
	return want, wantErr
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func clip(b []byte) []byte {
	if len(b) > 16 {
		return b[:16]
	}
	return b
}

// matchBlockMax is one block holding a match at the largest distance the
// format can name: offset slot 63, all 26 extra bits set, low offset 15.
func matchBlockMax(last bool) []byte {
	var w handBits
	w.match()
	w.put(0, 1)        // offset slot 63
	w.put(1<<26-1, 26) // every extra bit
	w.put(0, 1)        // low offset 15
	return handBlock(&w, last)
}

// The largest distance, 1 + (3<<30) + ((1<<26 - 1) << 4) + 15 = 1<<32, does
// not fit an item's uint32 as itself; the item must still carry it intact,
// and replay must put exactly what the serial path computes into the
// distance history.
// Mutation check: store uint32(distance) in decodeBlockItems and add nothing
// back in replayItems, and d.offset[0] is 0.
func TestItemCarriesLargestDistance(t *testing.T) {
	cl := handTables(63, 15)
	ts := &tableSet{}
	ts.prewarm()
	if err := ts.load(cl); err != nil {
		t.Fatal(err)
	}
	blk := matchBlockMax(true)
	h, err := readBlockHead(bytes.NewReader(blk), new([5]byte))
	if err != nil {
		t.Fatal(err)
	}
	payload := blk[len(blk)-h.blockBytes:]

	br := newBitReader(payload, h.blockBits)
	if sym, err := ts.main.ReadSym(br); err != nil || sym != 262 {
		t.Fatalf("symbol = %d, %v, want 262", sym, err)
	}
	_, want, err := decodeOffsetBits(br, ts, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strconv.IntSize == 64 && int64(want) != 1<<32 {
		t.Fatalf("setup: serial distance %d, want %d", want, int64(1)<<32)
	}

	j := &blockJob{payload: payload, bits: h.blockBits, tables: ts, items: make([]item, itemCap)}
	decodeBlockItems(j)
	if j.err != nil || j.n != 1 || j.items[0].kind != itemMatch {
		t.Fatalf("items: err = %v, n = %d, first %+v; want one match", j.err, j.n, j.items[0])
	}
	d := newDecoder50()
	d.init(nil, true)
	win := newWindow(minWindowSize)
	if err := win.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	idx := 0
	_, _ = d.replayItems(win, j, &idx, 1<<30) // the copy is refused; the history is what is checked
	if d.offset[0] != want {
		t.Fatalf("replayed distance %d, serial %d", d.offset[0], want)
	}
}

// The same match after a full window of history, with a header that
// declares a 4 GiB dictionary: serial refuses it as a capacity limit, and
// every mode must deliver the same bytes and the same error.
// Mutation check: as above; the worker mode reports ErrWindowOffsetBounds
// for distance 0.
func TestLargestDistanceAgreesWithSerial(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("the distance wraps on 32-bit ints, on both paths")
	}
	data := append(literalBlocks(minWindowSize, 32000), matchBlockMax(true)...)
	got, err := compareModes(t, handTables(63, 15), data, maxDictSize)
	if !errors.Is(err, ErrDictionaryTooLarge) || len(got) != minWindowSize {
		t.Fatalf("setup: serial delivered %d bytes then %v, want %d then ErrDictionaryTooLarge",
			len(got), err, minWindowSize)
	}
}

// Running out of bits inside a symbol does not end the block on the serial
// path: Read swallows ErrDecoderOutOfData, and the next fill resumes the same
// block from the bits that symbol left, then moves on. Each mode must do the
// same.
//
// The truncated symbol is a match whose offset slot 8 wants 3 extra bits.
// "tail" leaves 2 bits behind it, which decode as two more literals; "next"
// leaves none, and a second block follows.
// Mutation check: pop the job on ErrDecoderOutOfData in fillParallel and the
// worker mode stops at "AAA"; let finishBlockInline keep its old error path
// and the inline mode stops at "AAA" in both cases.
func TestOutOfDataResumesTheSameBlock(t *testing.T) {
	cl := handTables(8, -1)
	truncated := func(w *handBits) {
		w.a()
		w.a()
		w.a()
		w.match()
		w.put(0, 1) // offset slot 8
	}
	var tail handBits
	truncated(&tail)
	tail.a()
	tail.a()
	var first, second handBits
	truncated(&first)
	for range 4 {
		second.b()
	}
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"tail", handBlock(&tail, true), "AAAAA"},
		{"next", append(handBlock(&first, false), handBlock(&second, true)...), "AAABBBB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compareModes(t, cl, tc.data, 0)
			if string(got) != tc.want || err != io.EOF {
				t.Fatalf("setup: serial %q then %v, want %q then EOF", got, err, tc.want)
			}
		})
	}
}

// A hard error in the symbol right after the one that reaches the fill
// target comes on the next Read on the serial path, after the staged bytes
// are delivered; it must on every path.
// Mutation check: return j.err from fillParallel as soon as the items are
// exhausted and the worker mode delivers nothing before the error.
func TestErrorAfterFillTargetDeliversStagedBytes(t *testing.T) {
	target := newWindow(minWindowSize).fillTarget()
	per := 32000
	data := literalBlocks(target-target%per, per)
	var w handBits
	for range target % per {
		w.a()
	}
	w.match() // against an empty offset table
	data = append(data, handBlock(&w, true)...)
	got, err := compareModes(t, handTables(-1, -1), data, 0)
	if len(got) != target || !errors.Is(err, ErrHuffDecodeFailed) {
		t.Fatalf("setup: serial delivered %d bytes then %v, want %d then ErrHuffDecodeFailed",
			len(got), err, target)
	}
	if strings.Trim(string(got), "A") != "" {
		t.Fatal("setup: serial delivered something other than literals")
	}
}
