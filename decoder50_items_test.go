package rarengine

import (
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
