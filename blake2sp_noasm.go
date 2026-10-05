//go:build !amd64 || purego

package rarengine

// blake2sp8 is the strided kernel entry point; this build has no SIMD kernel.
func blake2sp8(h *[8][8]uint32, p []byte, t uint64) {
	blake2sp8Generic(h, p, t)
}
