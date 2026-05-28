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
func (w *Window) Reset(keepHistory bool) {
	if !keepHistory {
		w.w = 0
		w.r = 0
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
func (w *Window) CopyBytes(length int, distance int) error {
	if distance <= 0 || distance > w.size {
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
