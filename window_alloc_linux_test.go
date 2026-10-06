//go:build linux

package rarengine

import "testing"

// decommit hands a grown window's pages back: a byte written before it reads
// as zero after it, while the reservation and its size survive. Mutation
// check: drop the MADV_DONTNEED call and the dirtied byte survives.
func TestDecommitReturnsPagesToTheKernel(t *testing.T) {
	w := newWindow(minWindowSize)
	if err := w.grow(1 << 20); err != nil {
		t.Fatal(err)
	}
	w.buf[0], w.buf[4096], w.buf[w.size-1] = 0xAA, 0xBB, 0xCC
	w.Reset(false)
	w.decommit()
	if w.buf[0] != 0 || w.buf[4096] != 0 || w.buf[w.size-1] != 0 {
		t.Fatalf("pages survived decommit: %x %x %x", w.buf[0], w.buf[4096], w.buf[w.size-1])
	}
	if w.size != 1<<20 || w.backing == nil {
		t.Fatal("decommit changed the size or dropped the reservation")
	}

	// A heap window has no pages to return and decommit must leave it alone.
	h := newWindow(minWindowSize)
	h.buf[0] = 0xAA
	h.decommit()
	if h.buf[0] != 0xAA {
		t.Fatal("decommit touched a heap window")
	}
}
