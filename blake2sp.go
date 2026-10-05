package rarengine

import (
	"encoding/binary"
	"math/bits"
)

// BLAKE2sp, the whole-file digest `rar -htb` records, built in-tree on the
// BLAKE2s compression function (RFC 7693).
//
// In-tree because the module requires only golang.org/x/sys, and because
// golang.org/x/crypto/blake2s would not serve in any case: it exposes no way
// to set the tree parameters (fanout, depth, node offset, node depth,
// inner length, last-node) this construction depends on.
//
// The structure, derived from the BLAKE2 specification and checked against
// hashlib.blake2s, unrar's own digest and rarfile's Blake2SP:
//
//   - eight leaf BLAKE2s hashers, leaf i with node offset i and node depth 0,
//     the last leaf (7) flagged last-node;
//   - the input is dealt to the leaves round-robin in 64-byte blocks, the
//     final partial block going to whichever leaf is next;
//   - a root BLAKE2s with node offset 0, node depth 1, last-node set, whose
//     input is the eight 32-byte leaf digests concatenated.
//
// Every one of the nine hashers is written with digest length 32, key length
// 0, fanout 8, depth 2, leaf length 0 and inner length 32.
//
// Everything here is a fixed-size value: Write allocates nothing, and
// nothing is retained between calls except the arrays below.

const (
	blake2sBlockSize = 64
	blake2spLeaves   = 8
	// Blake2spSize is the digest length in bytes.
	blake2spSize = 32
)

var blake2sIV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var blake2sSigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// blake2s is one BLAKE2s hasher in tree mode. It holds back the final block
// until more input arrives or sum is called, because the last block is
// compressed with the finalisation flags set and a hasher cannot know a block
// is the last until the input ends.
type blake2s struct {
	h        [8]uint32
	t        uint64
	buf      [blake2sBlockSize]byte
	n        int
	lastNode bool
}

// init starts a hasher for one node of a BLAKE2sp tree.
func (s *blake2s) init(nodeOffset uint64, nodeDepth uint8, lastNode bool) {
	*s = blake2s{lastNode: lastNode}
	// The parameter block as eight little-endian words: digest length 32, key
	// length 0, fanout 8, depth 2 | leaf length 0 | node offset (48 bits) |
	// node depth, inner length 32 | salt and personalisation, all zero.
	s.h = blake2sIV
	s.h[0] ^= 32 | 0<<8 | blake2spLeaves<<16 | 2<<24
	s.h[2] ^= uint32(nodeOffset)
	s.h[3] ^= uint32(nodeOffset>>32)&0xFFFF | uint32(nodeDepth)<<16 | 32<<24
}

func (s *blake2s) write(p []byte) {
	for len(p) > 0 {
		// A full buffer is only compressed once more input proves it is not
		// the last block.
		if s.n == blake2sBlockSize {
			s.t += blake2sBlockSize
			s.compress(&s.buf, false)
			s.n = 0
		}
		if s.n == 0 {
			// Whole blocks straight from the caller's slice, leaving at least
			// one byte behind to be buffered.
			for len(p) > blake2sBlockSize {
				s.t += blake2sBlockSize
				s.compress((*[blake2sBlockSize]byte)(p), false)
				p = p[blake2sBlockSize:]
			}
		}
		c := copy(s.buf[s.n:], p)
		s.n += c
		p = p[c:]
	}
}

// sum finalises the hasher. It consumes the state: call it once.
func (s *blake2s) sum() [blake2spSize]byte {
	s.t += uint64(s.n)
	clear(s.buf[s.n:])
	s.compress(&s.buf, true)
	var out [blake2spSize]byte
	for i, w := range s.h {
		binary.LittleEndian.PutUint32(out[4*i:], w)
	}
	return out
}

func (s *blake2s) compress(block *[blake2sBlockSize]byte, final bool) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[4*i:])
	}
	v := [16]uint32{
		s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7],
		blake2sIV[0], blake2sIV[1], blake2sIV[2], blake2sIV[3],
		blake2sIV[4] ^ uint32(s.t), blake2sIV[5] ^ uint32(s.t>>32),
		blake2sIV[6], blake2sIV[7],
	}
	if final {
		v[14] = ^v[14]
		if s.lastNode {
			v[15] = ^v[15]
		}
	}
	for r := range blake2sSigma {
		sg := &blake2sSigma[r]
		blake2sG(&v, 0, 4, 8, 12, m[sg[0]], m[sg[1]])
		blake2sG(&v, 1, 5, 9, 13, m[sg[2]], m[sg[3]])
		blake2sG(&v, 2, 6, 10, 14, m[sg[4]], m[sg[5]])
		blake2sG(&v, 3, 7, 11, 15, m[sg[6]], m[sg[7]])
		blake2sG(&v, 0, 5, 10, 15, m[sg[8]], m[sg[9]])
		blake2sG(&v, 1, 6, 11, 12, m[sg[10]], m[sg[11]])
		blake2sG(&v, 2, 7, 8, 13, m[sg[12]], m[sg[13]])
		blake2sG(&v, 3, 4, 9, 14, m[sg[14]], m[sg[15]])
	}
	for i := range s.h {
		s.h[i] ^= v[i] ^ v[i+8]
	}
}

func blake2sG(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -12)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -7)
}

// blake2sp is a streaming BLAKE2sp hasher. The zero value is NOT ready: use
// init. It is a plain value and Write never allocates.
type blake2sp struct {
	leaf [blake2spLeaves]blake2s
	// buf collects a 64-byte block that has not yet been handed to a leaf,
	// and cur is the leaf that block belongs to.
	buf [blake2sBlockSize]byte
	n   int
	cur int
}

// blake2spStride is the input one trip round the leaves consumes: eight
// 64-byte blocks, one for each leaf.
const blake2spStride = blake2spLeaves * blake2sBlockSize

// blake2spMaxCallStrides bounds the strides handed to one kernel call, 64 KiB
// of input, so a huge Write never sits in non-preemptible assembly for long.
const blake2spMaxCallStrides = 128

//go:generate go run -C asm -mod=readonly blake2sp_gen.go -pkg rarengine -out ../blake2sp_amd64.s -stubs ../blake2sp_amd64.go

// blake2sp8Generic compresses len(p)/blake2spStride strides of p, none of them
// the last block of anything, into eight leaf states held transposed in h
// (word j of leaf i is h[j][i]); leaf i takes bytes 64*i..64*i+63 of each
// stride. t is the byte counter the first block of each leaf ends at, and
// advances by 64 per stride. It is the reference every SIMD kernel must match;
// the per-architecture blake2sp8 picks between them.
func blake2sp8Generic(h *[8][8]uint32, p []byte, t uint64) {
	var s blake2s
	for ; len(p) >= blake2spStride; p = p[blake2spStride:] {
		t += blake2sBlockSize
		for lane := range blake2spLeaves {
			for j := range s.h {
				s.h[j] = h[j][lane]
			}
			s.t = t
			s.compress((*[blake2sBlockSize]byte)(p[blake2sBlockSize*lane:]), false)
			for j := range s.h {
				h[j][lane] = s.h[j]
			}
		}
	}
}

// blake2spStrideHook, when non-nil, is told the byte length of every kernel
// call. It exists for tests to observe that the strided path ran.
var blake2spStrideHook func(n int)

// blake2sp8Chunked runs blake2sp8 over p, a whole number of strides, in calls
// of at most blake2spMaxCallStrides, and returns the advanced counter.
func blake2sp8Chunked(h *[8][8]uint32, p []byte, t uint64) uint64 {
	for len(p) > 0 {
		n := min(len(p), blake2spMaxCallStrides*blake2spStride)
		if blake2spStrideHook != nil {
			blake2spStrideHook(n)
		}
		blake2sp8(h, p[:n], t)
		t += uint64(n/blake2spStride) * blake2sBlockSize
		p = p[n:]
	}
	return t
}

// dealStrides deals every whole stride of p to the leaves, which must be
// block-aligned (cur == 0), and returns what is left. At least one block per
// leaf is always held back, exactly as the one-block-at-a-time path does,
// because only sum knows which block is the last.
//
// Leaves are always in step when cur == 0: every one has buffered a full
// block or none has seen input yet, so the kernel sees eight equal counters.
func (s *blake2sp) dealStrides(p []byte) []byte {
	k := len(p) / blake2spStride
	if k == 0 {
		return p
	}
	// Scratch lives on the stack: the leaf states transposed so word j of
	// leaf i is lanes[j][i], and the held-back blocks laid out as one stride.
	var lanes [8][8]uint32
	var stage [blake2spStride]byte
	t := s.leaf[0].t
	for i := range s.leaf {
		for j, w := range s.leaf[i].h {
			lanes[j][i] = w
		}
	}
	if s.leaf[0].n == blake2sBlockSize {
		// The held-back blocks now provably are not last: compress them.
		for i := range s.leaf {
			copy(stage[blake2sBlockSize*i:], s.leaf[i].buf[:])
		}
		t = blake2sp8Chunked(&lanes, stage[:], t)
	}
	t = blake2sp8Chunked(&lanes, p[:(k-1)*blake2spStride], t)
	last := p[(k-1)*blake2spStride:]
	for i := range s.leaf {
		l := &s.leaf[i]
		for j := range l.h {
			l.h[j] = lanes[j][i]
		}
		l.t = t
		copy(l.buf[:], last[blake2sBlockSize*i:])
		l.n = blake2sBlockSize
	}
	return p[k*blake2spStride:]
}

func (s *blake2sp) init() {
	for i := range s.leaf {
		s.leaf[i].init(uint64(i), 0, i == blake2spLeaves-1)
	}
	s.n, s.cur = 0, 0
}

func (s *blake2sp) deal(block []byte) {
	s.leaf[s.cur].write(block)
	s.cur = (s.cur + 1) % blake2spLeaves
}

func (s *blake2sp) Write(p []byte) (int, error) {
	total := len(p)
	if s.n > 0 {
		c := copy(s.buf[s.n:], p)
		s.n += c
		p = p[c:]
		if s.n < blake2sBlockSize {
			return total, nil
		}
		s.deal(s.buf[:])
		s.n = 0
	}
	for len(p) >= blake2sBlockSize {
		if s.cur == 0 && len(p) >= blake2spStride {
			p = s.dealStrides(p)
			continue
		}
		s.deal(p[:blake2sBlockSize])
		p = p[blake2sBlockSize:]
	}
	s.n = copy(s.buf[:], p)
	return total, nil
}

// sum returns the digest. It consumes the state: call it once.
func (s *blake2sp) sum() [blake2spSize]byte {
	if s.n > 0 {
		s.deal(s.buf[:s.n])
		s.n = 0
	}
	var root blake2s
	root.init(0, 1, true)
	for i := range s.leaf {
		d := s.leaf[i].sum()
		root.write(d[:])
	}
	return root.sum()
}
