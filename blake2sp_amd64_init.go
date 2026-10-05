//go:build amd64 && !purego

package rarengine

import (
	"golang.org/x/sys/cpu"
)

// useAVX2 reports whether blake2sp8 runs the AVX2 kernel. It is set once at
// init and read thereafter; tests flip it to compare the two paths.
var useAVX2 bool

func init() {
	useAVX2 = cpu.X86.HasAVX2
}

// blake2sp8 is the strided kernel entry point; see blake2sp8Generic for the
// contract. The caller guarantees len(p) >= blake2spStride. The kernel is
// called directly rather than through a function variable so that its
// //go:noescape holds and the caller's scratch can stay on the stack.
func blake2sp8(h *[8][8]uint32, p []byte, t uint64) {
	if useAVX2 {
		blake2sp8AVX2(h, &p[0], len(p)/blake2spStride, t)
		return
	}
	blake2sp8Generic(h, p, t)
}
