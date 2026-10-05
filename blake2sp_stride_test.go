package rarengine

import (
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

func TestBlake2spStridedMatchesOneBlockAtATime(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	sizes := make([]int, 0, 4200)
	for n := 0; n <= 4096; n++ {
		sizes = append(sizes, n)
	}
	sizes = append(sizes, 1<<20, 1<<20+1, 1<<20+511, 1<<20+512, 3*512*1024+37)
	for name, use := range blake2sp8Modes() {
		t.Run(name, func(t *testing.T) {
			use(t)
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
	for name, use := range blake2sp8Modes() {
		t.Run(name, func(t *testing.T) {
			use(t)
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
	blake2spStrideHook = func(n int) {
		calls++
		bytesSeen += n
	}
	t.Cleanup(func() { blake2spStrideHook = nil })
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

// One kernel call never covers more than blake2spMaxCallStrides strides, so a
// huge Write cannot hold a thread in non-preemptible assembly for long, and
// the counter carried between the calls must stay right.
func TestBlake2spKernelCallsAreBounded(t *testing.T) {
	const limit = blake2spMaxCallStrides * blake2spStride
	var calls, biggest int
	blake2spStrideHook = func(n int) {
		calls++
		biggest = max(biggest, n)
	}
	t.Cleanup(func() { blake2spStrideHook = nil })
	data := blake2spPattern(2*limit + 5*blake2spStride + 33)
	var h blake2sp
	h.init()
	_, _ = h.Write(data)
	if biggest > limit {
		t.Fatalf("a kernel call covered %d bytes, limit %d", biggest, limit)
	}
	if calls < 3 {
		t.Fatalf("%d bytes took %d kernel calls, want at least 3", len(data), calls)
	}
	if got, want := h.sum(), blake2spOneBlockSum(data); got != want {
		t.Fatalf("digest %x, want %x", got, want)
	}
}
