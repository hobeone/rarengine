package rarengine

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"testing"
)

// A copy must keep decoding what the source decoded, and a later load into
// the source must not reach it.
func TestTableSetCopyFromIsIndependent(t *testing.T) {
	// Flat codes over the first 1<<bits main symbols: complete trees, so
	// Init accepts them, and different bits give different symbol orders.
	flat := func(cl []byte, bits int) {
		clear(cl)
		for i := range 1 << bits {
			cl[i] = byte(bits)
		}
	}
	var cl [tableSize5]byte
	flat(cl[:mainSize5], 4)
	var src tableSet
	src.prewarm()
	if err := src.load(cl[:]); err != nil {
		t.Fatal(err)
	}
	var dst tableSet
	dst.copyFrom(&src)
	want := slices.Clone(dst.main.symbol)

	flat(cl[:mainSize5], 3)
	if err := src.load(cl[:]); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dst.main.symbol, want) {
		t.Fatal("load on the source changed the copy's symbols")
	}
	if slices.Equal(src.main.symbol, want) {
		t.Fatal("test did not change the source's symbols, so it proves nothing")
	}
}

// serialBlocks decodes the first compressed member of file with the serial
// decoder, one block at a time, and returns for each block the bytes it
// wrote into the window, and the window size the member needed (the reader
// grows it to the dictionary). The window is drained after every symbol so that
// "bytes written" is observable without a second window.
func serialBlocks(t *testing.T, file string) (blocks [][]byte, jobs []*blockJob, winSize int) {
	t.Helper()
	r := NewReader(fileVolumesOf(t, file))
	t.Cleanup(func() { _ = r.Close() })
	firstCompressedMember(t, r)
	d, win := r.dec50, r.win
	drain := make([]byte, win.size)
	for {
		if err := d.readBlockHeader(); err != nil {
			t.Fatalf("readBlockHeader: %v", err)
		}
		// Snapshot the block for the item decoder: payload copy, bit count,
		// the tables in force.
		j := &blockJob{
			payload:   bytes.Clone(d.payloadBuf),
			bits:      d.bitReader.limit,
			lastBlock: d.lastBlock,
			tables:    &tableSet{},
			items:     make([]item, itemCap),
			done:      make(chan struct{}, 1),
		}
		j.tables.copyFrom(&d.tables)
		// The worker starts after the tables; so must the snapshot.
		j.resume = d.bitReader
		j.resume.buf = j.payload // d.payloadBuf is reused by the next block
		jobs = append(jobs, j)

		var out []byte
		for {
			sym, err := d.tables.main.ReadSym(d.br)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("ReadSym: %v", err)
			}
			if err := d.decodeSymbol(win, sym); err != nil {
				t.Fatalf("decodeSymbol: %v", err)
			}
			n, _ := win.Read(drain)
			out = append(out, drain[:n]...)
		}
		blocks = append(blocks, out)
		if d.lastBlock {
			return blocks, jobs, win.size
		}
		d.br = nil
	}
}

func firstCompressedMember(t *testing.T, r *Reader) *Entry {
	t.Helper()
	for {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("no compressed member: %v", err)
		}
		if e.Header.Method != 0 {
			return e
		}
		if _, err := io.Copy(io.Discard, e); err != nil {
			t.Fatal(err)
		}
	}
}

// Decoding a block to items and replaying them writes exactly the bytes the
// serial loop wrote, block for block: on a real multi-block member, and on a
// member whose blocks carry filter records. The exe case also requires that
// an itemFilter was produced, so it cannot pass without the filter arm.
// Mutation check: pass int(it.aux)&1 as the slot in replayItems' itemRepDist
// arm, or store distance+1 in decodeBlockItems' itemMatch, and the first
// block's bytes differ. A mutation inside applyMatch would not do: serial
// and replay share it.
func TestReplayMatchesSerialBlockForBlock(t *testing.T) {
	for _, tc := range []struct {
		file        string
		minBlocks   int
		wantFilters bool
	}{
		{"rar5_solid_bench.rar", 10, false},
		{"rar5_exe_filter.rar", 1, true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			blocks, jobs, winSize := serialBlocks(t, filepath.Join("testdata", tc.file))
			if len(blocks) < tc.minBlocks {
				t.Fatalf("fixture has %d blocks, need at least %d", len(blocks), tc.minBlocks)
			}

			// A fresh decoder and window replay from the snapshots.
			d := newDecoder50()
			d.init(nil, true)
			win := newWindow(winSize)
			if err := win.BeginFile(false); err != nil {
				t.Fatal(err)
			}
			drain := make([]byte, win.size)
			filters := 0
			for i, j := range jobs {
				// j.resume was snapshotted right after readBlockHeader, so it
				// is positioned after the block's tables: exactly where the
				// dispatcher will leave it for a worker.
				decodeBlockItems(j)
				if j.err != nil {
					t.Fatalf("block %d: worker error %v", i, j.err)
				}
				if j.partial {
					t.Fatalf("block %d: overflowed %d items", i, itemCap)
				}
				for _, it := range j.items[:j.n] {
					if it.kind == itemFilter {
						filters++
					}
				}
				var out []byte
				idx := 0
				for {
					exhausted, err := d.replayItems(win, j, &idx, 1)
					if err != nil {
						t.Fatalf("block %d: replay %v", i, err)
					}
					n, _ := win.Read(drain)
					out = append(out, drain[:n]...)
					if exhausted {
						break
					}
				}
				if !bytes.Equal(out, blocks[i]) {
					t.Fatalf("block %d: replay wrote %d bytes, serial wrote %d (first difference at %d)",
						i, len(out), len(blocks[i]), firstDiff(out, blocks[i]))
				}
			}
			if tc.wantFilters && filters == 0 {
				t.Fatal("no itemFilter produced; the filter arm was not exercised")
			}
			if tc.wantFilters && len(d.fl) == 0 {
				t.Fatal("replay queued no filters")
			}
		})
	}
}

// replayItems on hand-built items: the filter pair, the queue-full check
// that precedes pairing, and the two malformed shapes.
// Mutation check: see each subtest.
func TestReplayItemsFilterArms(t *testing.T) {
	setup := func(t *testing.T) (*decoder50, *window) {
		t.Helper()
		d := newDecoder50()
		d.init(nil, true)
		win := newWindow(minWindowSize)
		if err := win.BeginFile(false); err != nil {
			t.Fatal(err)
		}
		return d, win
	}
	run := func(d *decoder50, win *window, items ...item) error {
		j := &blockJob{items: items, n: len(items)}
		idx := 0
		_, err := d.replayItems(win, j, &idx, 1<<30)
		return err
	}

	// Mutation: queue start := offset instead of d.decoded+offset and the
	// start is 7, not 107.
	t.Run("pair queues one filter", func(t *testing.T) {
		d, win := setup(t)
		d.decoded = 100
		err := run(d, win,
			item{kind: itemFilter, aux: 1, value: 7},
			item{kind: itemFilterLen, value: 64})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.fl) != 1 || d.fl[0].start != 107 || d.fl[0].length != 64 || d.fl[0].ftype != 1 {
			t.Fatalf("queued %+v, want one filter at 107 of length 64 type 1", d.fl)
		}
	})
	// Mutation: move the queue-full check after the pairing check and the
	// error becomes ErrCorruptDecodeHeader (the lone itemFilter here has no
	// length item).
	t.Run("full queue refused before pairing", func(t *testing.T) {
		d, win := setup(t)
		d.fl = d.fl[:0]
		for range maxQueuedFilters {
			d.fl = append(d.fl, filterBlock{})
		}
		err := run(d, win, item{kind: itemFilter})
		if !errors.Is(err, ErrTooManyFilters) {
			t.Fatalf("err = %v, want ErrTooManyFilters", err)
		}
	})
	// Mutation: delete the `*idx >= j.n` operand of the guard and the read
	// of items[*idx] panics (or passes a stale item).
	t.Run("trailing filter without length", func(t *testing.T) {
		d, win := setup(t)
		err := run(d, win, item{kind: itemFilter})
		if !errors.Is(err, ErrCorruptDecodeHeader) {
			t.Fatalf("err = %v, want ErrCorruptDecodeHeader", err)
		}
	})
	// Mutation: add `case itemFilterLen:` beside itemRepLast and the stray
	// item is silently applied instead of refused.
	t.Run("stray filter length", func(t *testing.T) {
		d, win := setup(t)
		err := run(d, win, item{kind: itemFilterLen, value: 5})
		if !errors.Is(err, ErrCorruptDecodeHeader) {
			t.Fatalf("err = %v, want ErrCorruptDecodeHeader", err)
		}
	})
}

// A block's bits decide how decodeBlockItems ends: a clean end is nil, and
// running out of bits inside a symbol is ErrDecoderOutOfData, as fill
// reports it.
// Mutation check: make mapInnerErr return err unchanged and the truncated
// case reports io.EOF; make decodeBlockItems record a clean io.EOF in j.err
// and the whole-block case fails.
func TestDecodeBlockItemsErrorIdentity(t *testing.T) {
	_, jobs, _ := serialBlocks(t, filepath.Join("testdata", "rar5_solid_bench.rar"))
	// decodeBlockItems advances j.resume, so each decode starts from a copy
	// of the pristine snapshot.
	orig := *jobs[0]
	whole := orig
	decodeBlockItems(&whole)
	if whole.err != nil || whole.partial {
		t.Fatalf("whole block: err = %v, partial = %v, want a clean end", whole.err, whole.partial)
	}

	// Cut bits off the end. A cut that lands on a symbol boundary (or inside
	// a main symbol, which ends the block) is a
	// clean, shorter block; one that lands inside a symbol must report
	// ErrDecoderOutOfData. Require at least one of the latter.
	sawOutOfData := false
	for cut := 1; cut <= 4096 && !sawOutOfData; cut++ {
		tj := orig
		tj.resume.limit -= cut
		decodeBlockItems(&tj)
		if tj.err == nil {
			continue
		}
		if !errors.Is(tj.err, ErrDecoderOutOfData) {
			t.Fatalf("cut %d: err = %v, want ErrDecoderOutOfData", cut, tj.err)
		}
		sawOutOfData = true
	}
	if !sawOutOfData {
		t.Fatal("no truncation landed inside a symbol")
	}
}

// A filter needs two item slots; with one left the worker must stop with
// the block partial and the resume position at the filter symbol, writing
// nothing.
// Mutation check: change the loop-top guard to `j.n >= len(j.items)` and
// the filter writes past the array (index out of range).
func TestDecodeBlockItemsFilterNeedsTwoSlots(t *testing.T) {
	_, jobs, _ := serialBlocks(t, filepath.Join("testdata", "rar5_exe_filter.rar"))
	var orig blockJob
	at := -1
	for _, c := range jobs {
		probe := *c
		decodeBlockItems(&probe)
		for i, it := range probe.items[:probe.n] {
			if it.kind == itemFilter {
				orig, at = *c, i
				break
			}
		}
		if at >= 0 {
			break
		}
	}
	if at < 0 {
		t.Fatal("fixture has no filter item")
	}

	// Room for the items before the filter and exactly one more slot.
	tj := orig
	tj.items = make([]item, at+1)
	sentinel := item{kind: itemRepLast, aux: 9, length: 9, value: 9}
	tj.items[at] = sentinel
	decodeBlockItems(&tj)
	if tj.err != nil || !tj.partial || tj.n != at {
		t.Fatalf("err = %v, partial = %v, n = %d; want nil, true, %d", tj.err, tj.partial, tj.n, at)
	}
	if tj.items[at] != sentinel {
		t.Fatalf("items[%d] = %+v was written although the pair did not fit", at, tj.items[at])
	}

	// Two slots: the pair fits.
	tj = orig
	tj.items = make([]item, at+3)
	decodeBlockItems(&tj)
	if tj.items[at].kind != itemFilter || tj.items[at+1].kind != itemFilterLen {
		t.Fatalf("with room, items[%d..] = %+v %+v, want filter and its length",
			at, tj.items[at], tj.items[at+1])
	}
}

func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// When the items fill up before the block ends, decoding resumes inline
// from the exact bit the worker stopped at, with the block's tables, and
// the bytes are still the serial bytes. The item array is made tiny so a
// real block overflows many times over.
// Mutation check: make finishBlockInline start from a fresh Reset of the
// payload instead of j.resume and every block's bytes differ.
func TestReplayResumesAfterItemOverflow(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	blocks, jobs, winSize := serialBlocks(t, file)

	d := newDecoder50()
	d.init(nil, true)
	win := newWindow(winSize)
	if err := win.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	drain := make([]byte, win.size)
	overflowed := 0
	for i, j := range jobs {
		j.items = make([]item, 64)
		var out []byte
		decodeBlockItems(j)
		if j.err != nil {
			t.Fatalf("block %d: %v", i, j.err)
		}
		idx := 0
		for {
			exhausted, err := d.replayItems(win, j, &idx, 1)
			if err != nil {
				t.Fatalf("block %d: replay %v", i, err)
			}
			n, _ := win.Read(drain)
			out = append(out, drain[:n]...)
			if exhausted {
				break
			}
		}
		if j.partial {
			overflowed++
			// Finish the block inline, draining as the serial loop did.
			for {
				done, err := d.finishBlockInline(win, j, 1)
				if err != nil {
					t.Fatalf("block %d: inline %v", i, err)
				}
				n, _ := win.Read(drain)
				out = append(out, drain[:n]...)
				if done {
					break
				}
			}
		}
		if !bytes.Equal(out, blocks[i]) {
			t.Fatalf("block %d: %d bytes, serial %d, first difference %d",
				i, len(out), len(blocks[i]), firstDiff(out, blocks[i]))
		}
	}
	t.Logf("%d blocks, %d overflowed", len(jobs), overflowed)
	if overflowed == 0 {
		t.Fatal("no block overflowed 64 items; the resume path was not exercised")
	}
}
