package rarengine

import (
	"errors"
)

// ErrWindowOffsetBounds is returned when copying bytes from an invalid history distance.
var ErrWindowOffsetBounds = errors.New("rarengine: window offset out of bounds")

// Window implements a zero-allocation, circular sliding window ring buffer for LZ77 decompression.
type Window struct {
	buf  []byte // Circular buffer slice
	size int    // Capacity of the circular buffer
	r    int    // Read index (beginning of unread data)
	w    int    // Write index (end of unread data)
	full bool   // True if the buffer is completely full

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
func (w *Window) historyLen() int {
	if w.wrapped {
		return w.size
	}
	return w.w
}

// NewWindow creates a new sliding window of the specified size.
func NewWindow(size int) *Window {
	// Minimum window size is 256KB (0x40000) per RAR spec.
	if size < 0x40000 {
		size = 0x40000
	}
	return &Window{
		buf:  make([]byte, size),
		size: size,
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
func (w *Window) Reset(keepHistory bool) {
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
func (w *Window) writeByte(c byte) {
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
func (w *Window) writeBytes(p []byte) {
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
func (w *Window) CopyBytes(length int, distance int) error {
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
func (w *Window) Available() int {
	if w.full {
		return w.size
	}
	if w.w >= w.r {
		return w.w - w.r
	}
	return w.size - w.r + w.w
}

// Read copies unread bytes from the window into p, advancing the read pointer.
func (w *Window) Read(p []byte) (int, error) {
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
func (w *Window) BeginFile(solid bool) error {
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
func (w *Window) MarkIncomplete() { w.incomplete = true }
