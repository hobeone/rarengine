//go:build amd64

package rarengine

// filterArmAVX2 relocates ARM branch targets using AVX2, returning the number of processed bytes.
func filterArmAVX2(buf []byte, offset int64) int
