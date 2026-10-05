//go:build !amd64 || purego

package rarengine

// blake2sp8Arch lists the architecture kernels this build has: none.
func blake2sp8Arch() map[string]func(*[8][8]uint32, []byte, uint64) { return nil }
