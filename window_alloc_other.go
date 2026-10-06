//go:build !linux

package rarengine

// defaultMaxWindow is the cap a Reader starts with where the window is a heap
// slice. A heap allocation is committed memory the moment it is made and a
// failed one is a fatal runtime error, not something a member can be refused
// for, so a 105-byte header declaring -md4g must not be able to ask for 4 GiB
// by default. 32 MiB is the window this library had before it followed the
// declaration; a consumer that wants more raises it with SetMaxWindow and
// accepts the heap cost.
const defaultMaxWindow = 32 << 20

// reserveWindowOS returns a zero-filled buffer of exactly size bytes.
//
// Off Linux the window is an ordinary heap allocation; see the Linux file for
// why a mapping is preferred where one is available. The release function is
// a no-op because the collector owns the memory.
func reserveWindowOS(size int) ([]byte, func(), error) {
	return make([]byte, size), func() {}, nil
}

// decommitWindow does nothing: heap memory has no pages to hand back short of
// dropping the buffer, and the buffer is kept so Reset stays allocation-free.
func decommitWindow([]byte) {}
