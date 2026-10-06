package rarengine

import (
	"bytes"
	"testing"
	"time"
)

// staleFullWindow builds the exact state window.Read used to hang on: full set
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

func staleFullWindow(t *testing.T, size, k int) *window {
	t.Helper()

	w := newWindow(size)
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

// TestWindowReadDoesNotSpinOnStaleFull pins that a window whose full flag no
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
// point, and giving window.Read one so a test can interrupt it would put
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

// TestMemberBoundaryClearsStaleFull documents why the two defects above are
// latent rather than reachable through the public API today, and pins the
// mechanism that makes them so.
//
// BeginFile resets r to w and clears full at every member boundary, both for
// a solid member and a non-solid one. Stale pointers therefore never survive
// into the next member. Since #94 a stored member does not touch the window
// at all, so the only writer is decoder50, which drains through Read; the
// reset is what would contain a future writer that did not.
//
// Recorded because the reachability argument depends entirely on this reset.
// A future path that writes the window without draining, or that admits a
// member without going through BeginFile, removes the mask and the
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
