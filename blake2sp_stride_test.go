package rarengine

import (
	"maps"
	"math/rand/v2"
	"testing"
)

// blake2spOneBlockSum hashes data the slow way, one 64-byte block at a time
// through deal and never through dealStrides. It is the oracle for the strided
// path: same leaves, same tail handling, none of the batching.
func blake2spOneBlockSum(data []byte) [blake2spSize]byte {
	var h blake2sp
	h.init()
	for len(data) >= blake2sBlockSize {
		h.deal(data[:blake2sBlockSize])
		data = data[blake2sBlockSize:]
	}
	if len(data) > 0 {
		h.deal(data)
	}
	return h.sum()
}

// blake2sp8Impls returns every implementation of the strided kernel the build
// can run, by name, so each is compared against the oracle in its own right
// rather than whichever one init happened to install.
func blake2sp8Impls() map[string]func(*[8][8]uint32, []byte, uint64) {
	impls := map[string]func(*[8][8]uint32, []byte, uint64){"generic": blake2sp8Generic}
	maps.Copy(impls, blake2sp8Arch())
	return impls
}

func withBlake2sp8(t *testing.T, f func(*[8][8]uint32, []byte, uint64)) {
	t.Helper()
	saved := blake2sp8
	blake2sp8 = f
	t.Cleanup(func() { blake2sp8 = saved })
}

func TestBlake2spStridedMatchesOneBlockAtATime(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	sizes := make([]int, 0, 4200)
	for n := 0; n <= 4096; n++ {
		sizes = append(sizes, n)
	}
	sizes = append(sizes, 1<<20, 1<<20+1, 1<<20+511, 1<<20+512, 3*512*1024+37)
	for name, impl := range blake2sp8Impls() {
		t.Run(name, func(t *testing.T) {
			withBlake2sp8(t, impl)
			for _, n := range sizes {
				data := make([]byte, n)
				for i := range data {
					data[i] = byte(rng.Uint32())
				}
				if got, want := blake2spSum(data), blake2spOneBlockSum(data); got != want {
					t.Fatalf("size %d: strided %x, one-block %x", n, got, want)
				}
			}
		})
	}
}

// Write calls of arbitrary size leave the hasher mid-block and mid-stride, so
// the strided path must start and stop at every alignment and still agree.
func TestBlake2spStridedAcrossArbitraryWrites(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	data := make([]byte, 200_000)
	for i := range data {
		data[i] = byte(rng.Uint32())
	}
	want := blake2spOneBlockSum(data)
	for name, impl := range blake2sp8Impls() {
		t.Run(name, func(t *testing.T) {
			withBlake2sp8(t, impl)
			for trial := range 50 {
				var h blake2sp
				h.init()
				rest := data
				for len(rest) > 0 {
					n := min(1+rng.IntN(5000), len(rest))
					if trial%2 == 0 && rng.IntN(4) == 0 {
						n = min(blake2spStride*(1+rng.IntN(4)), len(rest))
					}
					_, _ = h.Write(rest[:n])
					rest = rest[n:]
				}
				if got := h.sum(); got != want {
					t.Fatalf("trial %d: %x, want %x", trial, got, want)
				}
			}
		})
	}
}

// The strided path must actually run: without this a regression that routed
// everything through deal would pass every equality test above.
func TestBlake2spWriteUsesTheStridedKernel(t *testing.T) {
	var calls, bytesSeen int
	withBlake2sp8(t, func(h *[8][8]uint32, p []byte, ctr uint64) {
		calls++
		bytesSeen += len(p)
		blake2sp8Generic(h, p, ctr)
	})
	data := blake2spPattern(10*blake2spStride + 100)
	var h blake2sp
	h.init()
	_, _ = h.Write(data)
	if calls == 0 || bytesSeen < 9*blake2spStride {
		t.Fatalf("kernel saw %d bytes in %d calls of %d written", bytesSeen, calls, len(data))
	}
	if got, want := h.sum(), blake2spOneBlockSum(data); got != want {
		t.Fatalf("digest %x, want %x", got, want)
	}
}
