package rarengine

import (
	"bytes"
	"errors"
	"testing"
)

func TestWindow_WriteAndRead(t *testing.T) {
	w := NewWindow(256 * 1024) // 256KB
	w.Reset(false)

	// Write 4 bytes
	w.writeByte('A')
	w.writeByte('B')
	w.writeByte('C')
	w.writeByte('D')

	if w.Available() != 4 {
		t.Errorf("expected 4 available bytes, got %d", w.Available())
	}

	out := make([]byte, 4)
	n, err := w.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 4 || !bytes.Equal(out, []byte("ABCD")) {
		t.Errorf("expected ABCD, got %s (n=%d)", out, n)
	}
	if w.Available() != 0 {
		t.Errorf("expected 0 available bytes, got %d", w.Available())
	}
}

func TestWindow_CopyBytes_Overlapping(t *testing.T) {
	w := NewWindow(256 * 1024)
	w.Reset(false)

	// Write 'X'
	w.writeByte('X')

	// Copy 5 bytes from distance 1 (should repeat 'X' 5 times)
	err := w.CopyBytes(5, 1)
	if err != nil {
		t.Fatalf("CopyBytes failed: %v", err)
	}

	if w.Available() != 6 {
		t.Errorf("expected 6 available bytes, got %d", w.Available())
	}

	out := make([]byte, 6)
	_, _ = w.Read(out)
	if !bytes.Equal(out, []byte("XXXXXX")) {
		t.Errorf("expected XXXXXX, got %s", out)
	}
}

func TestWindow_CopyBytes_InvalidOffset(t *testing.T) {
	w := NewWindow(256 * 1024)
	w.Reset(false)

	// Copy from distance 0 (invalid)
	err := w.CopyBytes(5, 0)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Errorf("expected ErrWindowOffsetBounds, got %v", err)
	}

	// Copy from distance larger than window size (invalid)
	err = w.CopyBytes(5, w.size+1)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Errorf("expected ErrWindowOffsetBounds, got %v", err)
	}

	// Copy from a distance inside the buffer but beyond anything written since
	// the reset. Nothing has been written at all here, so the valid history is
	// empty and every distance is out of bounds — including 1.
	err = w.CopyBytes(5, 1)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Errorf("expected ErrWindowOffsetBounds, got %v", err)
	}
}

// TestWindow_CopyBytes_HistoryEdge pins the accept/reject boundary at exactly
// the depth of history produced so far. The cases differ only in how that
// history was produced, which is the property under test: history is history
// regardless of which writer emitted it, so all three writers must feed the
// same bound.
//
// Each case asserts the rejected side first. An accepted copy advances the
// write pointer and therefore moves the edge, so checking acceptance first
// would invalidate the rejection assertion that follows it.
func TestWindow_CopyBytes_HistoryEdge(t *testing.T) {
	tests := []struct {
		name string
		// build produces some history and returns its depth in bytes. It takes
		// the subtest's own *testing.T: Fatalf calls FailNow, which must run on
		// the goroutine of the test it is failing.
		build func(t *testing.T, w *Window) int
	}{
		{
			name: "byte at a time",
			build: func(_ *testing.T, w *Window) int {
				w.writeByte('A')
				return 1
			},
		},
		{
			name: "bulk write",
			build: func(_ *testing.T, w *Window) int {
				w.writeBytes([]byte("STORED"))
				return 6
			},
		},
		{
			name: "output of an earlier copy",
			build: func(t *testing.T, w *Window) int {
				w.writeBytes([]byte("AB"))
				if err := w.CopyBytes(2, 2); err != nil {
					t.Fatalf("setup copy failed: %v", err)
				}
				return 4
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWindow(0x40000)
			w.Reset(false)

			depth := tc.build(t, w)
			if got := w.historyLen(); got != depth {
				t.Fatalf("setup produced %d bytes of history, want %d", got, depth)
			}

			if err := w.CopyBytes(1, depth+1); !errors.Is(err, ErrWindowOffsetBounds) {
				t.Errorf("distance %d with %d bytes of history should be rejected, got %v",
					depth+1, depth, err)
			}
			if err := w.CopyBytes(1, depth); err != nil {
				t.Errorf("distance %d with %d bytes of history should be accepted, got %v",
					depth, depth, err)
			}
		})
	}
}

// drainAll reads the window empty, discarding the contents.
func drainAll(w *Window) {
	buf := make([]byte, 4096)
	for {
		n, _ := w.Read(buf)
		if n == 0 {
			return
		}
	}
}

// fillWindowWithPriorFile simulates a previously decompressed file: it fills
// the window with recognizable content and drains it, leaving those bytes
// physically present in buf but logically consumed. It does not reset — the
// caller chooses whether the next file is solid.
//
// The marker is deliberately greppable so a leak shows up as readable text in a
// failure message rather than as an opaque byte count.
func fillWindowWithPriorFile(w *Window) {
	w.writeBytes(bytes.Repeat([]byte("SECRET-A"), w.size/8))
	drainAll(w)
}

// TestWindow_CopyBytes_DoesNotLeakPriorFile is the regression test for the
// history-disclosure bug: a back-reference reaching past what the current file
// has written used to return the previous file's decompressed bytes, because
// Reset(false) deliberately does not clear the buffer.
func TestWindow_CopyBytes_DoesNotLeakPriorFile(t *testing.T) {
	w := NewWindow(0x40000)
	fillWindowWithPriorFile(w)

	// A new non-solid file begins: pointers reset, buffer deliberately not cleared.
	w.Reset(false)

	// That file emits a back-reference before writing anything.
	err := w.CopyBytes(16, 1000)
	if !errors.Is(err, ErrWindowOffsetBounds) {
		t.Fatalf("over-reaching back-reference accepted: %v", err)
	}

	// The error must not come with data. Nothing may be readable.
	if got := w.Available(); got != 0 {
		out := make([]byte, got)
		n, _ := w.Read(out)
		t.Fatalf("rejected copy still produced %d bytes: %q", got, out[:n])
	}
}

// TestWindow_CopyBytes_SolidPreservesHistory guards the other direction: the
// bound must not reject references a solid file is entitled to make into the
// preceding file's dictionary.
func TestWindow_CopyBytes_SolidPreservesHistory(t *testing.T) {
	w := NewWindow(0x40000)
	w.Reset(false)

	w.writeBytes([]byte("HISTORY!"))
	drain := make([]byte, 8)
	if _, err := w.Read(drain); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// A solid file continues the previous file's dictionary.
	w.Reset(true)

	if err := w.CopyBytes(8, 8); err != nil {
		t.Fatalf("solid back-reference into preserved history rejected: %v", err)
	}
	out := make([]byte, 8)
	if _, err := w.Read(out); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !bytes.Equal(out, []byte("HISTORY!")) {
		t.Errorf("expected HISTORY!, got %q", out)
	}

	// Still bounded. History is now 16 bytes — the 8 carried across the solid
	// reset plus the 8 the copy above produced — so 17 is out of reach and 16
	// is not. Reading does not move the write pointer, so the drain above left
	// the depth alone.
	if err := w.CopyBytes(1, 17); !errors.Is(err, ErrWindowOffsetBounds) {
		t.Errorf("distance 17 with 16 bytes of history should be rejected, got %v", err)
	}
	if err := w.CopyBytes(1, 16); err != nil {
		t.Errorf("distance 16 with 16 bytes of history should be accepted, got %v", err)
	}
}

// TestWindow_Reset_ClearsWrapped pins the internal representation, not the
// public contract. It exists because CLAUDE.md's Security Constraints name
// `wrapped` specifically: the flag is what distinguishes "w is 0 because the
// ring lapped" from "w is 0 because history was discarded", and getting that
// backwards reopens the disclosure.
//
// A refactor that replaces the wrapped/w pair with some other representation
// may legitimately rewrite this test. What it may NOT change is the accept and
// reject behavior of CopyBytes itself, pinned by HistoryEdge,
// DoesNotLeakPriorFile and SolidPreservesHistory. Those tests also read
// historyLen as a setup self-check, which such a refactor may adjust — but
// their CopyBytes assertions must keep passing unchanged.
func TestWindow_Reset_ClearsWrapped(t *testing.T) {
	w := NewWindow(0x40000)
	w.Reset(false)

	w.writeBytes(bytes.Repeat([]byte("x"), w.size))
	if !w.wrapped {
		t.Fatalf("writing size bytes should have lapped the ring")
	}
	if got := w.historyLen(); got != w.size {
		t.Errorf("expected full history depth %d, got %d", w.size, got)
	}

	// Preserving reset keeps the lap; a solid file may still reach back.
	w.Reset(true)
	if !w.wrapped {
		t.Errorf("Reset(true) must not discard history")
	}
	if got := w.historyLen(); got != w.size {
		t.Errorf("expected history depth %d after Reset(true), got %d", w.size, got)
	}

	// Non-preserving reset discards the right to reference it.
	w.Reset(false)
	if w.wrapped {
		t.Errorf("Reset(false) must discard history")
	}
	if got := w.historyLen(); got != 0 {
		t.Errorf("expected history depth 0 after Reset(false), got %d", got)
	}
}

// TestWindow_LapMakesFullDepthReachable covers the case where the derived depth
// diverges from the raw write pointer: once the ring laps, w falls back toward
// zero while the whole buffer is legitimately addressable, so a bound taken
// from w alone would start rejecting most of a solid file's dictionary.
//
// Each of the three writers maintains the lap flag on its own, so each gets a
// case here. The CopyBytes case matters most: it is the only writer whose lap
// store nothing else would exercise, and losing it would silently over-reject
// after a copy-driven lap.
func TestWindow_LapMakesFullDepthReachable(t *testing.T) {
	tests := []struct {
		name string
		// lap advances the write pointer through at least one full lap,
		// draining as it goes so w never overruns r. It takes the subtest's own
		// *testing.T: Fatalf calls FailNow, which must run on the goroutine of
		// the test it is failing.
		lap func(t *testing.T, w *Window)
	}{
		{
			name: "writeByte",
			lap: func(_ *testing.T, w *Window) {
				for range w.size {
					w.writeByte('z')
					if w.Available() == 4096 {
						drainAll(w)
					}
				}
			},
		},
		{
			name: "writeBytes",
			lap: func(_ *testing.T, w *Window) {
				chunk := bytes.Repeat([]byte("y"), 4096)
				for range w.size/len(chunk) + 1 {
					w.writeBytes(chunk)
					drainAll(w)
				}
			},
		},
		{
			name: "CopyBytes",
			lap: func(t *testing.T, w *Window) {
				w.writeBytes(bytes.Repeat([]byte("x"), 4096))
				drainAll(w)
				for range w.size/4096 + 1 {
					if err := w.CopyBytes(4096, 4096); err != nil {
						t.Fatalf("setup copy failed: %v", err)
					}
					drainAll(w)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWindow(0x40000)
			w.Reset(false)

			tc.lap(t, w)

			if !w.wrapped {
				t.Fatalf("ring should have lapped")
			}
			if w.w > w.size/2 {
				t.Fatalf("write pointer should have fallen back after lapping, got %d", w.w)
			}
			if got := w.historyLen(); got != w.size {
				t.Fatalf("expected full depth %d after lap, got %d", w.size, got)
			}
			// A distance of the full window is now legitimate even though w is small.
			if err := w.CopyBytes(4, w.size); err != nil {
				t.Errorf("full-depth back-reference after lap rejected: %v", err)
			}
		})
	}
}

func TestWindow_Wraparound(t *testing.T) {
	// Let's force a small window size (which falls back to minWindowSize = 256KB = 262144 bytes)
	w := NewWindow(10)
	w.Reset(false)

	// Write 262140 bytes
	for range 262140 {
		w.writeByte('A')
	}

	// Read them all to clear read buffer
	drainAll(w)

	// Write 10 bytes (this will trigger wraparound at 262144)
	// indices: 262140, 262141, 262142, 262143 (index 0, 1, 2, 3, 4, 5)
	for i := range 10 {
		w.writeByte(byte('0' + i))
	}

	if w.Available() != 10 {
		t.Errorf("expected 10 available bytes, got %d", w.Available())
	}

	out := make([]byte, 10)
	n, err := w.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 10 || !bytes.Equal(out, []byte("0123456789")) {
		t.Errorf("expected 0123456789, got %s (n=%d)", out, n)
	}
}

func TestWindow_CompletelyFull(t *testing.T) {
	w := NewWindow(10)
	w.Reset(false)
	size := w.size

	for i := range size {
		w.writeByte(byte(i % 256))
	}

	if !w.full {
		t.Errorf("expected window to be full")
	}
	if w.Available() != size {
		t.Errorf("expected %d available bytes, got %d", size, w.Available())
	}

	out := make([]byte, size)
	n, err := w.Read(out)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != size {
		t.Errorf("expected read of %d bytes, got %d", size, n)
	}
	if w.full {
		t.Errorf("expected window to be no longer full after read")
	}
	if w.Available() != 0 {
		t.Errorf("expected 0 available bytes, got %d", w.Available())
	}

	for i := range size {
		if out[i] != byte(i%256) {
			t.Errorf("data mismatch at index %d: expected %d, got %d", i, byte(i%256), out[i])
			break
		}
	}
}

func TestWindowBeginFileRefusesSolidAfterIncomplete(t *testing.T) {
	w := NewWindow(0x40000)

	if err := w.BeginFile(false); err != nil {
		t.Fatalf("first BeginFile(false): %v", err)
	}
	w.writeBytes([]byte("hello"))
	w.MarkIncomplete()

	if err := w.BeginFile(true); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("BeginFile(true) after MarkIncomplete = %v, want ErrSolidStreamBroken", err)
	}
}

func TestWindowBeginFileNonSolidClearsIncomplete(t *testing.T) {
	w := NewWindow(0x40000)
	w.MarkIncomplete()

	// A non-solid file resets the history, so nothing it or its successors
	// reference depends on what the damaged file failed to write.
	if err := w.BeginFile(false); err != nil {
		t.Fatalf("BeginFile(false) after MarkIncomplete: %v", err)
	}
	if err := w.BeginFile(true); err != nil {
		t.Fatalf("BeginFile(true) after a clean non-solid file: %v", err)
	}
}
