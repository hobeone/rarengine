//go:build !linux

package rarengine

// reserveWindow returns a zero-filled buffer of exactly size bytes.
//
// Off Linux the window is an ordinary heap allocation; see the Linux file for
// why a mapping is preferred where one is available. The release function is
// a no-op because the collector owns the memory.
func reserveWindow(size int) ([]byte, func(), error) {
	return make([]byte, size), func() {}, nil
}

// decommitWindow does nothing: heap memory has no pages to hand back short of
// dropping the buffer, and the buffer is kept so Reset stays allocation-free.
func decommitWindow([]byte) {}
