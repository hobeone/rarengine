package rarengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

// staleFullWindow builds the exact state Window.Read used to hang on: full set
// while w and r do not describe a full buffer, with w landed on 0.
//
// The sequence matters, so it is spelled out rather than assigned directly --
// a test that pokes the fields cannot show the state is reachable through the
// type's own API, which is the whole question.
//
//	writeBytes(k)    w=k r=0
//	Read(k)          w=k r=k full=false
//	writeBytes(size) w wraps to 0, then lands exactly on r=k -> full=true
//	writeBytes(size-k) w wraps to 0 again; full is never cleared
//
// leaving w=0, r=k, full=true. Available() then reports the whole buffer,
// which is what sends Read looking for bytes that are not there.
// staleK is the read-pointer offset staleFullWindow is built with. The short
// read the two tests below assert is size-staleK, so it lives here rather than
// being repeated as a literal in three places.
const staleK = 100

func staleFullWindow(t *testing.T, size, k int) *Window {
	t.Helper()

	w := NewWindow(size)
	size = w.size // NewWindow enforces a minimum

	w.writeBytes(bytes.Repeat([]byte{'a'}, k))
	if n, _ := w.Read(make([]byte, k)); n != k {
		t.Fatalf("setup drain read %d bytes, want %d", n, k)
	}
	w.writeBytes(bytes.Repeat([]byte{'b'}, size))
	if !w.full {
		t.Fatalf("setup: full not set; w=%d r=%d", w.w, w.r)
	}
	w.writeBytes(bytes.Repeat([]byte{'c'}, size-k))

	if w.w != 0 || w.r != k || !w.full {
		t.Fatalf("setup produced w=%d r=%d full=%v, want w=0 r=%d full=true",
			w.w, w.r, w.full, k)
	}
	return w
}

// TestWindowReadDoesNotSpinOnStaleFull pins that a Window whose full flag no
// longer matches its pointers produces a short read rather than hanging.
//
// The loop copied until it had moved Available() bytes and had no exit for a
// copy that moved nothing. With full stale, Available() over-reports, the
// second iteration computes end == w.r, and copy returns 0 forever.
//
// A hang is the worst failure this library can produce: the stack points at
// Read rather than at whatever left the state inconsistent, and a consumer
// decompressing untrusted archives cannot attribute it. Turning it into a
// short read makes a bad state observable at the point it is used.
//
// Run in a goroutine because the failure mode under test is non-termination:
// asserting on it directly would hang the suite instead of failing it.
//
// On failure that goroutine is left spinning for the rest of the run, which is
// accepted rather than fixed: the loop it is stuck in has no cancellation
// point, and giving Window.Read one so a test can interrupt it would put
// production machinery in the hot path to serve a case that only occurs when
// the code is already broken. A failing run is not expected to be a long one.
func TestWindowReadDoesNotSpinOnStaleFull(t *testing.T) {
	w := staleFullWindow(t, 0x40000, staleK)

	done := make(chan int, 1)
	go func() {
		n, _ := w.Read(make([]byte, w.size))
		done <- n
	}()

	select {
	case n := <-done:
		// Asserted exactly, not as a range. Read can never exceed len(p),
		// so "n > w.size" is a bound that cannot fail -- and n == w.size is
		// precisely the regression to catch: a Read that returned the
		// over-reported Available() instead of what it moved. The ring holds
		// size-k readable bytes from r to the end of the buffer, and the
		// second iteration finds nothing, so that is the whole answer.
		if want := w.size - staleK; n != want {
			t.Fatalf("Read returned %d bytes, want exactly %d -- the short "+
				"count is the assertion, and %d would mean Available()'s "+
				"over-report was passed straight through", n, want, w.size)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Window.Read did not return: the copy loop made no progress " +
			"and has no exit for it")
	}
}

// TestWindowReadReportsWhatItActuallyMoved is the other half: a short read is
// only useful if the count is honest. A loop that gave up but still returned
// Available() would report bytes it never wrote into p.
func TestWindowReadReportsWhatItActuallyMoved(t *testing.T) {
	w := staleFullWindow(t, 0x40000, staleK)

	p := make([]byte, w.size)
	for i := range p {
		p[i] = 0xff
	}
	n, _ := w.Read(p)

	// Asserted before the loop below, which iterates from n: if Read
	// over-reported n as len(p), that loop would run zero times and the test
	// would pass having verified nothing.
	if want := w.size - staleK; n != want {
		t.Fatalf("Read returned %d bytes, want %d", n, want)
	}

	for i := n; i < len(p); i++ {
		if p[i] != 0xff {
			t.Fatalf("Read reported %d bytes but wrote at index %d", n, i)
		}
	}
}

// TestStoreReaderLeavesWindowPointersConsistent covers the source of that
// state: storeReader records every byte it delivers as history so a solid
// successor can back-reference it, but it never reads from the window, so
// nothing advanced r behind the writes.
//
// Once w laps r, full and Available stop describing the buffer. The fix is
// not a drain -- there is nothing to drain, the bytes went to the caller
// straight from the source -- but recording them as history that is already
// accounted for, which is what they are.
//
// Mutation check: change storeReader.Read back to win.writeBytes and this
// fails on the pointer assertions.
func TestStoreReaderLeavesWindowPointersConsistent(t *testing.T) {
	win := NewWindow(0x40000)
	// Three and a bit laps, in chunks that do not divide the window, so a
	// chunk boundary lands on r at some point rather than by construction.
	content := bytes.Repeat([]byte("stored member payload. "), 60000)
	if len(content) < 3*win.size {
		t.Fatalf("fixture is %d bytes, need more than %d to lap the window",
			len(content), 3*win.size)
	}

	s := &storeReader{r: bytes.NewReader(content), win: win}
	got := make([]byte, 0, len(content))
	buf := make([]byte, 7919) // prime, so chunks straddle the ring boundary
	for {
		n, err := s.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			// Only io.EOF ends this loop. Breaking on any error let a
			// mid-stream failure end the read silently and surface as a
			// content-length mismatch below, naming the wrong cause.
			if !errors.Is(err, io.EOF) {
				t.Fatalf("storeReader.Read after %d bytes: %v", len(got), err)
			}
			break
		}
	}

	// The member's own bytes are unaffected: they come from the source, not
	// from the window. This is the regression guard on the fix itself.
	if !bytes.Equal(got, content) {
		t.Fatalf("storeReader delivered %d bytes, want %d", len(got), len(content))
	}
	if win.full {
		t.Error("full is set after a store pass: nothing is pending in the " +
			"window, so nothing can be full")
	}
	if win.r != win.w {
		t.Errorf("r=%d w=%d: a stored member leaves nothing unread, so the "+
			"pointers must not diverge", win.r, win.w)
	}
	if avail := win.Available(); avail != 0 {
		t.Errorf("Available() = %d, want 0", avail)
	}
	// The history itself must survive -- that is why storeReader touches the
	// window at all. A full lap means the whole buffer is referenceable.
	if !win.wrapped || win.historyLen() != win.size {
		t.Errorf("wrapped=%v historyLen=%d, want true and %d: a solid "+
			"successor must still reach the stored member's bytes",
			win.wrapped, win.historyLen(), win.size)
	}
}

// A solid member following a large stored one must still be able to
// back-reference the stored bytes. This is the property the window write
// exists for, asserted end to end so the fix cannot quietly drop it.
func TestSolidSuccessorReachesStoredHistory(t *testing.T) {
	win := NewWindow(0x40000)
	content := bytes.Repeat([]byte("stored member payload. "), 60000)

	s := &storeReader{r: bytes.NewReader(content), win: win}
	if _, err := io.Copy(io.Discard, s); err != nil {
		t.Fatalf("store pass: %v", err)
	}

	// The solid successor opens on the history the stored member left.
	if err := win.BeginFile(true); err != nil {
		t.Fatalf("BeginFile(solid): %v", err)
	}
	// Reach back into it, at the deepest distance the window allows.
	if err := win.CopyBytes(64, win.size-1); err != nil {
		t.Fatalf("CopyBytes at the full window depth: %v", err)
	}
	out := make([]byte, 64)
	n, _ := win.Read(out)
	if n != 64 {
		t.Fatalf("read %d bytes back from the solid copy, want 64", n)
	}
	if bytes.Equal(out, make([]byte, 64)) {
		t.Fatal("solid successor read zeroes: the stored member's history " +
			"was not recorded")
	}
}

// TestMemberBoundaryClearsStaleFull documents why the two defects above are
// latent rather than reachable through the public API today, and pins the
// mechanism that makes them so.
//
// BeginFile resets r to w and clears full at every member boundary, both for
// a solid member and a non-solid one. A stored member's stale pointers
// therefore never survive into the member that would read the window, and
// nothing reads it during the stored member itself -- storeReader delivers
// from its source. That is why a 40 MB stored member laps the window and
// still round-trips byte-for-byte, before and after the fix.
//
// Recorded because the reachability argument depends entirely on this reset.
// A future path that reads the window during a stored member, or that admits
// a member without going through BeginFile, removes the mask and the
// underlying bug becomes live -- so the test that documents the mask belongs
// next to the fix, not in a commit message.
func TestMemberBoundaryClearsStaleFull(t *testing.T) {
	for _, solid := range []bool{false, true} {
		w := staleFullWindow(t, 0x40000, staleK)
		if err := w.BeginFile(solid); err != nil {
			t.Fatalf("BeginFile(%v): %v", solid, err)
		}
		if w.full || w.r != w.w {
			t.Errorf("BeginFile(solid=%v) left full=%v r=%d w=%d; the stale "+
				"state must not survive a member boundary",
				solid, w.full, w.r, w.w)
		}
		if avail := w.Available(); avail != 0 {
			t.Errorf("BeginFile(solid=%v): Available() = %d, want 0", solid, avail)
		}
	}
}
