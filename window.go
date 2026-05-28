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
}

// WriteByte writes a single byte to the window.
func (w *Window) WriteByte(c byte) {
	w.buf[w.w] = c
	w.w++
	if w.w >= w.size {
		w.w = 0
	}
}

// CopyBytes copies 'length' bytes from 'distance' bytes back in history to the current write pointer.
// Supports overlapping copies (e.g. repeating patterns where length > distance).
func (w *Window) CopyBytes(length int, distance int) error {
	if distance <= 0 || distance > w.size {
		return ErrWindowOffsetBounds
	}

	srcIdx := w.w - distance
	if srcIdx < 0 {
		srcIdx += w.size
	}

	for range length {
		b := w.buf[srcIdx]
		w.buf[w.w] = b

		srcIdx++
		if srcIdx >= w.size {
			srcIdx = 0
		}

		w.w++
		if w.w >= w.size {
			w.w = 0
		}
	}
	return nil
}

// Available returns the number of unread bytes in the window.
func (w *Window) Available() int {
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

	copied := 0
	for copied < n {
		end := w.w
		if w.w < w.r {
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
