package rarengine

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// Abandoning a compressed member leaves the shared decoder holding a bit
// reader positioned inside that member's compressed block, because a member
// larger than half the window is not decoded to its end before the caller
// moves on. decoder50.init points the decoder at the next member's bytes,
// so those buffered bits belong to a stream the decoder is no longer
// reading; decoding resumed from them, against Huffman tables the abandoned
// member left behind.
//
// Mutation check: remove "d.br = nil" from decoder50.init and this test
// fails with "window offset out of bounds" -- the second member yields
// nothing at all, and so would every member after it.
func TestAbandoningALargeMemberDoesNotBreakTheNext(t *testing.T) {
	// huge.bin is 17 MB -- past the window's half-fill threshold, so the
	// first fill stops mid-block -- and is mostly a repeating pattern, with
	// enough incompressible noise ahead of it to stay under the rar-bomb
	// ratio that would otherwise refuse it before it ever decoded.
	data, err := os.ReadFile("testdata/rar5_abandon_large.rar")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan io.ReadCloser, 1)
	ch <- io.NopCloser(bytes.NewReader(data))
	close(ch)

	r := NewReader(ch)
	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if _, err := io.ReadFull(first, make([]byte, 1024)); err != nil {
		t.Fatalf("partial read of %q: %v", first.Header.Name, err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	n, err := io.Copy(io.Discard, second)
	if err != nil {
		t.Fatalf("%q: read after abandoning %q: %v", second.Header.Name, first.Header.Name, err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("%q: Close: %v", second.Header.Name, err)
	}
	if n != second.Header.UnpackedSize {
		t.Fatalf("%q: produced %d bytes, header declares %d", second.Header.Name, n, second.Header.UnpackedSize)
	}
}
