//go:build !amd64 || purego

package rarengine

import "testing"

// blake2sp8Modes names every way this build can run the strided path, each a
// function that selects it for the test. Without a SIMD kernel there is one.
func blake2sp8Modes() map[string]func(*testing.T) {
	return map[string]func(*testing.T){"generic": func(*testing.T) {}}
}
