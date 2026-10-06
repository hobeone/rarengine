//go:build linux

package rarengine

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// decommit hands a large grown window's pages back: a byte written before it
// reads as zero after it, while the reservation and its size survive. Mutation
// check: drop the MADV_DONTNEED call and the dirtied byte survives.
func TestDecommitReturnsPagesToTheKernel(t *testing.T) {
	w := newWindow(minWindowSize)
	if err := w.grow(64 << 20); err != nil {
		t.Fatal(err)
	}
	w.buf[0], w.buf[4096], w.buf[w.size-1] = 0xAA, 0xBB, 0xCC
	w.Reset(false)
	w.decommit()
	if w.buf[0] != 0 || w.buf[4096] != 0 || w.buf[w.size-1] != 0 {
		t.Fatalf("pages survived decommit: %x %x %x", w.buf[0], w.buf[4096], w.buf[w.size-1])
	}
	if w.size != 64<<20 || w.backing == nil {
		t.Fatal("decommit changed the size or dropped the reservation")
	}

	// At or below the threshold the pages stay, as the fixed 32 MiB window's
	// always did: refaulting them is a per-archive memclr nobody asked for.
	small := newWindow(minWindowSize)
	if err := small.grow(decommitThreshold); err != nil {
		t.Fatal(err)
	}
	small.buf[0] = 0xAA
	small.Reset(false)
	small.decommit()
	if small.buf[0] != 0xAA {
		t.Fatal("decommit touched a window at the threshold")
	}

	// A heap window has no pages to return and decommit must leave it alone.
	h := newWindow(minWindowSize)
	h.buf[0] = 0xAA
	h.decommit()
	if h.buf[0] != 0xAA {
		t.Fatal("decommit touched a heap window")
	}
}

// The Reader decommits on the traversal goroutine at two moments: end of
// archive, for the caller that builds a Reader per archive and never Resets,
// and Reset, for the caller that reuses one. Both leave the first page of a
// 64 MiB window zero after the member wrote into it. Mutation check: remove
// either call and its case fails.
func TestReaderDecommitsAtEndOfArchiveAndOnReset(t *testing.T) {
	// A member whose dictionary is above the threshold. rar5_dict_64m.rar's
	// single member is small but compressed, so it writes the window's first
	// bytes.
	read := func(r *Reader) {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}
		if _, err := io.Copy(io.Discard, e); err != nil {
			t.Fatalf("Read: %v", err)
		}
		if r.win.size != 64<<20 {
			t.Fatalf("window = %d, want 64 MiB", r.win.size)
		}
		if r.win.buf[0] == 0 {
			t.Fatal("setup: the member left the window's first byte zero, so the test cannot see a decommit")
		}
	}

	t.Run("end of archive", func(t *testing.T) {
		r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_64m.rar")))
		defer r.Close() //nolint:errcheck
		read(r)
		if _, err := r.NextEntry(); !errors.Is(err, io.EOF) {
			t.Fatalf("NextEntry at end = %v, want io.EOF", err)
		}
		if r.win.buf[0] != 0 {
			t.Fatal("pages still resident after the archive ended")
		}
	})
	t.Run("Reset", func(t *testing.T) {
		r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_64m.rar")))
		defer r.Close() //nolint:errcheck
		read(r)
		// Reset before the end of the archive is seen, so this is Reset's
		// own decommit and not the end-of-archive one.
		r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_store.rar")))
		if r.win.buf[0] != 0 {
			t.Fatal("pages still resident after Reset")
		}
	})
}
