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
	e := firstCompressedMember(t, r)
	d, win := r.dec50, r.win
	_ = e
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
// serial loop wrote, block for block, on a real multi-block member.
// Mutation check: make applyMatch rotate the history in the wrong order and
// the second block's bytes differ.
func TestReplayMatchesSerialBlockForBlock(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	blocks, jobs, winSize := serialBlocks(t, file)
	if len(blocks) < 10 {
		t.Fatalf("fixture has %d blocks, need a multi-block member", len(blocks))
	}

	// A fresh decoder and window replay from the snapshots.
	d := newDecoder50()
	d.init(nil, true)
	win := newWindow(winSize)
	if err := win.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	drain := make([]byte, win.size)
	for i, j := range jobs {
		// j.resume was snapshotted right after readBlockHeader, so it is
		// positioned after the block's tables: exactly where the dispatcher
		// will leave it for a worker.
		decodeBlockItems(j)
		if j.err != nil {
			t.Fatalf("block %d: worker error %v", i, j.err)
		}
		if j.partial {
			t.Fatalf("block %d: overflowed %d items", i, itemCap)
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
