package rarengine

import (
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

// blake2spPattern is the input the known-answer vectors below were computed
// over. The same formula is in the Python oracle (see the comment on
// blake2spKnownAnswers), so the two sides never share a byte buffer, only a
// definition.
func blake2spPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7 + (i>>8)*17)
	}
	return b
}

func blake2spSum(data []byte) [blake2spSize]byte {
	var h blake2sp
	h.init()
	_, _ = h.Write(data)
	return h.sum()
}

// blake2spKnownAnswers were produced by a Python oracle that composes BLAKE2sp
// out of hashlib.blake2s with the tree parameters set explicitly:
//
//	b(off, depth, last) = hashlib.blake2s(digest_size=32, fanout=8, depth=2,
//	    leaf_size=0, inner_size=32, node_offset=off, node_depth=depth,
//	    last_node=last)
//	leaf i = b(i, 0, i == 7); blocks of 64 dealt round-robin;
//	root = b(0, 1, True) fed the eight leaf digests.
//
// That oracle agrees with rarfile's Blake2SP at 0, 1, 64, 513, 4096 and 70000
// bytes, and with the digest `rar -htb` stored for two real archives
// (600000 random bytes: 0463d404..., and a 4.9 MB text file: 69d003aa...),
// which is how the construction is known to be BLAKE2sp as RAR means it
// rather than merely consistent with itself.
//
// The lengths straddle every boundary that has its own code: empty, a
// partial block, exactly one block, one over, 8 blocks less one byte (the
// last lane gets a partial block), exactly 8 blocks (every lane one full
// block, and the last-node leaf must still finalise), one over, a few
// rounds of lanes, and a large odd length that wraps the round-robin many
// times.
var blake2spKnownAnswers = []struct {
	n   int
	hex string
}{
	{0, "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"},
	{1, "49029041da5d740e916f0cd6f1b864f9130c2df21baf9736394faf991f96ec23"},
	{63, "8137b07fb096af5f7268ffb48817b291e6f38551a6cd700e9eb293bb54d60ded"},
	{64, "729e406c0c10ccbaf82118fbb3932c7ace02b4bbb24e8a2a9720485baa92fe97"},
	{65, "c06f2218cbc3cf7b9f19828fcac7fc0f6f53b0579bb31318b95fc1306b7549b8"},
	{511, "9fc6920732d82634939a0739b37d3277e02ea0895d6cc0ed448b04f13b8fe52d"},
	{512, "f07b64b80510fa9cf50c99a815af6f438b69569b8bc8a70ca91d9bff9f316ae7"},
	{513, "5a6600affc95307282f1933b01da1aebaafc3441d2a0000db4bc024e64872f0f"},
	{4096, "dae252cbd23ed4e45713cc73a117c7c73af32c6fa1f6a4c5d13d3925f5455ee5"},
	{1048576 + 12345, "dc7ae75302c69fb5b91d8734050464f4b350081993935d3de1935649c2b7bdce"},
}

func TestBlake2spKnownAnswers(t *testing.T) {
	for _, tc := range blake2spKnownAnswers {
		got := blake2spSum(blake2spPattern(tc.n))
		if hex.EncodeToString(got[:]) != tc.hex {
			t.Errorf("n=%d: got %x, want %s", tc.n, got, tc.hex)
		}
	}
}

// Feeding the same bytes in arbitrary pieces must give the digest of one
// write. Block-boundary bugs live here: a piece that ends mid-block, one that
// completes a buffered block and carries on, one of exactly 64 bytes, and
// zero-length writes.
func TestBlake2spStreamingInvariance(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{0, 1, 63, 64, 65, 511, 512, 513, 4096, 100003} {
		data := blake2spPattern(n)
		want := blake2spSum(data)
		for trial := range 25 {
			var h blake2sp
			h.init()
			rest := data
			for len(rest) > 0 {
				// A mix of tiny pieces, block-sized ones and large ones.
				var k int
				switch rng.IntN(4) {
				case 0:
					k = rng.IntN(3)
				case 1:
					k = 64
				case 2:
					k = rng.IntN(200)
				default:
					k = rng.IntN(5000)
				}
				k = min(k, len(rest))
				_, _ = h.Write(rest[:k])
				rest = rest[k:]
			}
			if got := h.sum(); got != want {
				t.Fatalf("n=%d trial=%d: pieces gave %x, one write gave %x",
					n, trial, got, want)
			}
		}
	}
}

// One byte at a time is the extreme case of the above and the one that
// exercises the buffered-block path on every call.
func TestBlake2spByteAtATime(t *testing.T) {
	data := blake2spPattern(2049)
	var h blake2sp
	h.init()
	for i := range data {
		_, _ = h.Write(data[i : i+1])
	}
	if got, want := h.sum(), blake2spSum(data); got != want {
		t.Fatalf("byte at a time gave %x, one write gave %x", got, want)
	}
}

func TestBlake2spWriteDoesNotAllocate(t *testing.T) {
	var h blake2sp
	h.init()
	buf := blake2spPattern(4096 + 17)
	if n := testing.AllocsPerRun(50, func() { _, _ = h.Write(buf) }); n != 0 {
		t.Fatalf("Write allocates %v times per call, want 0", n)
	}
}

func BenchmarkBlake2sp(b *testing.B) {
	buf := blake2spPattern(1 << 20)
	var h blake2sp
	h.init()
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		_, _ = h.Write(buf)
	}
}
