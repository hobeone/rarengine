//go:build amd64

package rarengine

// filterE8ScanAVX2 scans buf for the first occurrence of 0xe8 or c using AVX2, returning its index.
func filterE8ScanAVX2(buf []byte, c byte) int
