//go:build amd64 && !purego

package rarengine

import (
	"math/rand/v2"
	"testing"

	"golang.org/x/sys/cpu"
)

// blake2sp8Modes names every way this build can run the strided path, each a
// function that selects it for the test and restores the default afterwards.
// The AVX2 mode is offered only where the CPU has AVX2, so a machine without it
// cannot silently compare the generic kernel with itself.
func blake2sp8Modes() map[string]func(*testing.T) {
	set := func(on bool) func(*testing.T) {
		return func(t *testing.T) {
			saved := useAVX2
			useAVX2 = on
			t.Cleanup(func() { useAVX2 = saved })
		}
	}
	modes := map[string]func(*testing.T){"generic": set(false)}
	if cpu.X86.HasAVX2 {
		modes["avx2"] = set(true)
	}
	return modes
}

// A machine with AVX2 must come up using it. Every equality test above selects
// its mode explicitly, so none would notice init failing to install the kernel.
func TestBlake2sp8InstallsAVX2WhenAvailable(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("CPU has no AVX2: the AVX2 kernel is not exercised on this machine")
	}
	if !useAVX2 {
		t.Fatal("CPU has AVX2 but blake2sp8 is not dispatching to the AVX2 kernel")
	}
}

// The kernel on its own, from arbitrary states, counters (including one that
// carries into the high word) and stride counts, against the generic loop.
func TestBlake2sp8AVX2MatchesGeneric(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("CPU has no AVX2: the AVX2 kernel is not exercised on this machine")
	}
	rng := rand.New(rand.NewPCG(5, 6))
	for _, strides := range []int{1, 2, 3, 7, 16} {
		for _, ctr := range []uint64{0, 64, 1 << 31, 1<<32 - 64*uint64(strides), 1<<32 - 64, 1<<40 + 12345*64} {
			var want, got [8][8]uint32
			for j := range want {
				for i := range want[j] {
					want[j][i] = rng.Uint32()
				}
			}
			got = want
			p := make([]byte, strides*blake2spStride)
			for i := range p {
				p[i] = byte(rng.Uint32())
			}
			blake2sp8Generic(&want, p, ctr)
			blake2sp8AVX2(&got, &p[0], strides, ctr)
			if got != want {
				t.Fatalf("strides %d counter %#x: kernel disagrees with generic", strides, ctr)
			}
		}
	}
	// Zero strides is a no-op, not a 2^64-iteration loop.
	var h, before [8][8]uint32
	h[0][0] = 7
	before = h
	var b byte
	blake2sp8AVX2(&h, &b, 0, 0)
	if h != before {
		t.Fatal("zero strides modified the state")
	}
}
