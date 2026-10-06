package rarengine

import (
	"errors"
	"runtime"
	"sync"
)

// ErrWindowOffsetBounds is returned when copying bytes from an invalid history distance.
var ErrWindowOffsetBounds = errors.New("rarengine: window offset out of bounds")

const (
	// minWindowSize is the smallest dictionary RAR5 can declare (128 KiB << 1)
	// and the size a Reader's window starts at, before any member has said
	// what it needs.
	minWindowSize = 0x40000

	// maxDictSize is the largest dictionary the format can express: the size
	// field is a 4-bit exponent over 128 KiB, so 128 KiB << 15. It is the
	// default MaxWindow.
	maxDictSize = 4 << 30

	// maxFillTarget caps how much decoded output decoder50.fill stages ahead
	// of the caller. It was size/2 when the window was a fixed 32 MiB, and for
	// that window it still is; a 4 GiB window must not stage 2 GiB before the
	// first byte is served, so the target no longer scales with the window.
	maxFillTarget = 16 << 20
)

// windowBacking owns one reservation's release. It is a separate object so a
// runtime cleanup can release a reservation whose window became unreachable
// without the cleanup holding the window itself, and so an explicit release
// (grow replacing it) and the cleanup cannot both run the munmap: free is
// idempotent.
type windowBacking struct {
	release func()
	once    sync.Once
}

func (b *windowBacking) free() {
	if b == nil || b.release == nil {
		return
	}
	b.once.Do(b.release)
}

// window implements a zero-allocation, circular sliding window ring buffer for LZ77 decompression.
type window struct {
	buf  []byte // Circular buffer slice
	size int    // Capacity of the circular buffer
	r    int    // Read index (beginning of unread data)
	w    int    // Write index (end of unread data)
	full bool   // True if the buffer is completely full

	// backing is the reservation behind buf when grow obtained one; nil for a
	// heap buffer from newWindow. It is what decommit and the next grow act on.
	backing *windowBacking

	// wrapped reports whether the ring has completed a full lap since the last
	// Reset that did not preserve history. Together with w it gives the true
	// depth of valid LZ77 history: w bytes before the first lap, the whole
	// buffer after. Bytes beyond that depth are stale contents of a previously
	// decompressed file, because Reset deliberately does not clear buf.
	//
	// w returns to 0 for two different reasons — Reset discarded history, or
	// the ring lapped — and this flag is what distinguishes them. Every path
	// that advances w must therefore maintain it. In non-test code there are
	// exactly three: writeByte, writeBytes, and CopyBytes.
	wrapped bool

	// incomplete records that the history holds something other than what a
	// solid successor's back-references assume: bytes missing because a member
	// ended short, wrong because it failed its CRC32, or absent because a
	// member was refused and never decoded at all.
	//
	// It lives here rather than beside the traversal because that is the
	// question it answers -- is this window still what a solid file may build
	// on. Previously the same state had four writers and a comment warning
	// that a fifth would have to answer the same question they did.
	//
	// The shortfall it describes sits INSIDE what CopyBytes bounds by: a
	// successor reads an earlier member's bytes rather than reading past the
	// written history, so the distance guard cannot catch it.
	incomplete bool
}

// historyLen returns the number of bytes of valid LZ77 history behind the write
// pointer. It is derived from w and wrapped rather than counted separately; see
// the wrapped field for why that is sound.
func (w *window) historyLen() int {
	if w.wrapped {
		return w.size
	}
	return w.w
}

// newWindow creates a new sliding window of the specified size on the heap.
//
// This is the window a Reader starts with, at minWindowSize, and the one
// tests build directly. A member that declares a larger dictionary grows it
// through grow, which swaps the heap buffer for a reservation.
func newWindow(size int) *window {
	// Minimum window size is 256KB (0x40000) per RAR spec.
	if size < minWindowSize {
		size = minWindowSize
	}
	return &window{
		buf:  make([]byte, size),
		size: size,
	}
}

// fillTarget is how much decoded output decoder50.fill stages before it
// returns to let the caller drain: half the window, capped at maxFillTarget.
//
// Half the window is the bound that keeps a decode step from overrunning the
// read pointer, because fill stops at least that far short of full and no
// single symbol produces more than a match length. The cap keeps a large
// window from turning that bound into gigabytes of latency and committed
// pages; for the 32 MiB window this library shipped with for years the two
// agree exactly, so that path is unchanged.
func (w *window) fillTarget() int {
	return min(w.size/2, maxFillTarget)
}

// grow replaces the buffer with a reservation of at least size bytes and
// discards the history, exactly as BeginFile(false) would. A size the window
// already meets is a no-op that keeps the history.
//
// It is called by Reader.dispatch for a non-solid member whose header declares
// a dictionary larger than the window holds, before that member's BeginFile.
// A solid member never reaches it: the caller refuses a solid member that
// declares more than the archive's window, because the history its
// back-references assume would be gone.
//
// Never called while an Entry can reach buf. The traversal has severed or
// finished the previous member before dispatch admits the next one, and that
// is the only goroutine that touches the window at all -- Close, the one
// method another goroutine may call, does not. That ordering is what makes
// releasing the old reservation here safe: nothing can read through a
// dangling slice because nothing holds one.
func (w *window) grow(size int) error {
	if size <= w.size {
		return nil
	}
	buf, release, err := reserveWindow(size)
	if err != nil {
		return err
	}
	old := w.backing
	w.buf, w.size = buf, size
	w.backing = &windowBacking{release: release}
	// The cleanup holds the backing, not the window, so a window that is no
	// longer reachable still has its reservation returned; an explicit free
	// from the next grow is absorbed by the Once.
	runtime.AddCleanup(w, (*windowBacking).free, w.backing)
	w.Reset(false)
	old.free()
	return nil
}

// decommit hands the window's pages back to the kernel while keeping the
// reservation, so the buffer is still the right size for the next archive and
// nothing was allocated to get there. The history is already discarded by the
// caller; see Reader.Reset for why this runs per archive and never per member.
func (w *window) decommit() {
	if w.backing != nil {
		decommitWindow(w.buf)
	}
}

// Reset resets the sliding window indexes. If keepHistory is true (for solid archives),
// we retain the written data and only reset the read pointer to the write pointer.
//
// The buffer is deliberately not cleared — see the note in CLAUDE.md. Discarding
// history therefore means discarding the right to reference it: wrapped is
// cleared alongside the pointers so CopyBytes rejects any back-reference into
// the previous file's bytes, which are still physically present in buf.
// A keepHistory reset leaves wrapped alone, so a solid group continues the
// preceding file's dictionary.
func (w *window) Reset(keepHistory bool) {
	if !keepHistory {
		w.w = 0
		w.r = 0
		w.wrapped = false
	} else {
		w.r = w.w
	}
	w.full = false
}

// writeByte writes a single byte to the window.
func (w *window) writeByte(c byte) {
	w.buf[w.w] = c
	w.w++
	if w.w >= w.size {
		w.w = 0
		w.wrapped = true
	}
	if w.w == w.r {
		w.full = true
	}
}

// writeBytes writes p to the window using bulk copy, handling ring wraparound.
// Semantics match repeated writeByte calls: full is set when w lands on r at a
// chunk boundary. Callers must drain via Read before w overruns r.
func (w *window) writeBytes(p []byte) {
	for len(p) > 0 {
		n := min(w.size-w.w, len(p))
		copy(w.buf[w.w:w.w+n], p[:n])
		w.w += n
		if w.w >= w.size {
			w.w = 0
			w.wrapped = true
		}
		if w.w == w.r {
			w.full = true
		}
		p = p[n:]
	}
}

// recordHistory adds p to the LZ77 history without staging it for Read.
//
// It exists for the stored path. A stored member's bytes reach the caller
// straight from the source and never pass through this buffer, but a solid
// successor may back-reference them, so they still have to enter the history.
// writeBytes is the wrong primitive for that: it stages bytes as unread and
// documents that the caller must "drain via Read before w overruns r", which a
// caller with no drain step cannot do. Once w lapped r, full and Available
// stopped describing the buffer.
//
// Syncing r to w says what is actually true -- these bytes are history, and
// nothing is pending -- so the ring's invariant holds by construction rather
// than by a caller remembering to drain. It is deliberately not Reset(true):
// that is a member-boundary transition, and this is not one.
//
// The history itself is unaffected: historyLen and CopyBytes are derived from
// w and wrapped, neither of which r participates in.
func (w *window) recordHistory(p []byte) {
	w.writeBytes(p)
	w.r = w.w
	w.full = false
}

// CopyBytes copies 'length' bytes from 'distance' bytes back in history to the
// current write pointer. Supports overlapping copies (e.g. repeating patterns
// where length > distance).
//
// Each iteration performs one runtime.memmove (via copy) of up to
//
//	min(remaining, distance, w.size - srcIdx, w.size - w.w)
//
// bytes. The `distance` cap preserves LZ77 pattern-repetition semantics: copy()
// has non-aliasing memmove semantics, so we must not let a single call cross
// the src/dst boundary. After copying d=distance bytes, src and dst advance by
// d together and remain exactly distance apart, keeping each subsequent copy
// non-overlapping.
//
// distance must lie within the history actually written since the last Reset
// that discarded history. A wider bound — the buffer size, say — would only
// prove the read lands inside buf, not that it lands on bytes this file
// produced; since Reset does not clear buf, the difference is the previous
// file's plaintext. Out-of-range distances return ErrWindowOffsetBounds and
// copy nothing. Callers driving the window directly should note this contract
// is narrower than a plain buffer-size bound.
func (w *window) CopyBytes(length int, distance int) error {
	// distance is attacker-controlled: it comes straight off the compressed
	// stream. historyLen never exceeds size, so this also keeps srcIdx in range.
	if distance <= 0 || distance > w.historyLen() {
		return ErrWindowOffsetBounds
	}

	srcIdx := w.w - distance
	if srcIdx < 0 {
		srcIdx += w.size
	}

	remaining := length
	for remaining > 0 {
		n := min(remaining, distance, w.size-srcIdx, w.size-w.w)
		copy(w.buf[w.w:w.w+n], w.buf[srcIdx:srcIdx+n])
		srcIdx += n
		if srcIdx >= w.size {
			srcIdx = 0
		}
		w.w += n
		if w.w >= w.size {
			w.w = 0
			w.wrapped = true
		}
		if w.w == w.r {
			w.full = true
		}
		remaining -= n
	}
	return nil
}

// Available returns the number of unread bytes in the window.
func (w *window) Available() int {
	if w.full {
		return w.size
	}
	if w.w >= w.r {
		return w.w - w.r
	}
	return w.size - w.r + w.w
}

// Read copies unread bytes from the window into p, advancing the read pointer.
func (w *window) Read(p []byte) (int, error) {
	avail := w.Available()
	if avail == 0 {
		return 0, nil
	}

	n := min(len(p), avail)
	wasFull := w.full
	if n > 0 {
		w.full = false
	}

	copied := 0
	for copied < n {
		end := w.w
		if w.w < w.r || (wasFull && copied == 0) {
			end = w.size
		}
		chunk := copy(p[copied:n], w.buf[w.r:end])
		if chunk == 0 {
			// Available() promised n bytes the ring cannot produce, which
			// means full was set while w and r do not describe a full
			// buffer. Without this the loop recomputes the same empty
			// range forever: nothing in the body moves a pointer when
			// chunk is 0, and there was no other exit.
			//
			// Reported as a short read rather than an error because Read's
			// signature has never produced one and callers do not check it
			// -- an error here would be discarded and the bad state would
			// go back to being invisible. A count lower than Available()
			// promised is something a caller acts on whether or not it
			// looks at the error.
			//
			// This is a backstop, not the fix. The state is prevented at
			// its source by recordHistory; see storeReader.
			break
		}
		w.r += chunk
		copied += chunk
		if w.r >= w.size {
			w.r = 0
		}
	}
	return copied, nil
}

// BeginFile prepares the window for a member.
//
// A non-solid member resets the history, so it and everything built on it are
// unaffected by earlier damage -- which is what clears the flag. A solid
// member after damage cannot be decoded correctly and is refused: its
// back-references reach into bytes its predecessors did not write, producing
// plausible-looking output with nothing in the format to mark it.
//
// It returns an error rather than a bool so that errcheck makes handling the
// refusal compulsory rather than customary.
func (w *window) BeginFile(solid bool) error {
	if solid {
		if w.incomplete {
			return ErrSolidStreamBroken
		}
		w.Reset(true)
		return nil
	}
	w.incomplete = false
	w.Reset(false)
	return nil
}

// MarkIncomplete records that the member just finished left the history in a
// state a solid successor's back-references do not assume.
//
// Called from what happened to the member -- it ended short, or failed its
// checksum, or was refused before decoding -- and never from the error a
// caller received. Those answer different questions: the caller's error asks
// "may traversal continue?", this asks "is the window intact?", and deriving
// one from the other left every non-continuable short member recorded as
// undamaged.
func (w *window) MarkIncomplete() { w.incomplete = true }
