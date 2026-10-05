//go:build ignore

// This generator emits blake2sp8AVX2, an 8-lane AVX2 BLAKE2s compression
// kernel: one 64-byte block for each of eight leaves per iteration, every
// 32-bit lane of a YMM register belonging to a different leaf.
//
// The approach (lane-per-leaf, message words transposed in registers, the
// round function expressed on whole vectors with the message schedule applied
// at generation time) follows nwaples/rardecode's asm/blake2sp_gen.go,
// Copyright (c) 2015, Nicholas Waples, BSD 2-Clause licence. That licence
// requires its copyright notice and disclaimer to be retained in source and
// binary redistributions; they are reproduced in full in THIRD_PARTY_NOTICES
// at the repository root (this directory is a separate module, so a notice
// kept here would not ship with the root module's zip). The kernel here differs from that one in taking raw input
// pointers rather than a pre-transposed context, so it transposes the
// message itself, and in looping over many strides with the counter kept in a
// general register.
//
// Run from the repository root with `go generate ./...`.
package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

var sigma = [10][16]byte{
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

var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

func y(i int) Register {
	return [...]Register{Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11, Y12, Y13, Y14, Y15}[i]
}

func main() {
	ConstraintExpr("amd64")

	ivSym := GLOBL("blake2sIV8", RODATA|NOPTR)
	for i, w := range iv {
		DATA(4*i, U32(w))
	}
	// VPSHUFB masks that rotate every 32-bit lane right by 16 and by 8 bits.
	rot16 := GLOBL("blake2sRot16", RODATA|NOPTR)
	for i := 0; i < 32; i++ {
		DATA(i, U8(byte(i&12)+byte((i+2)&3)))
	}
	rot8 := GLOBL("blake2sRot8", RODATA|NOPTR)
	for i := 0; i < 32; i++ {
		DATA(i, U8(byte(i&12)+byte((i+1)&3)))
	}

	TEXT("blake2sp8AVX2", NOSPLIT, "func(h *[8][8]uint32, p *byte, strides int, t uint64)")
	Doc("blake2sp8AVX2 compresses strides consecutive 512-byte strides of p into the",
		"eight BLAKE2s states in h, lane i of h[j] being word j of leaf i and leaf i",
		"taking bytes 64*i..64*i+63 of every stride. t is the byte counter the first",
		"block ends at; it advances by 64 per stride. No block is final.",
		"",
		"The design follows nwaples/rardecode's asm/blake2sp_gen.go, Copyright (c)",
		"2015, Nicholas Waples, BSD 2-Clause licence; its notice and disclaimer are",
		"reproduced in THIRD_PARTY_NOTICES at the repository root.")
	Pragma("noescape")

	hPtr := Load(Param("h"), GP64())
	pPtr := Load(Param("p"), GP64())
	n := Load(Param("strides"), GP64())
	t := Load(Param("t"), GP64())

	m := AllocLocal(16 * 32)
	v14 := AllocLocal(32)
	v15 := AllocLocal(32)

	TESTQ(n, n)
	JZ(LabelRef("done"))

	Label("stride")

	// Message words: for each half of the 64-byte blocks, load eight rows (one
	// per leaf), transpose 8x8, and park word j of all leaves at m[j].
	for half := 0; half < 2; half++ {
		for lane := 0; lane < 8; lane++ {
			VMOVDQU(Mem{Base: pPtr, Disp: 64*lane + 32*half}, y(lane))
		}
		// a(2k), a(2k+1) = low/high dword interleave of rows 2k, 2k+1, in Y8..Y15.
		for k := 0; k < 4; k++ {
			VPUNPCKLDQ(y(2*k+1), y(2*k), y(8+2*k))
			VPUNPCKHDQ(y(2*k+1), y(2*k), y(8+2*k+1))
		}
		// Quadword interleave. b0..b3 combine rows 0-3 (a0..a3), b4..b7 rows 4-7
		// (a4..a7); each b holds word j in its low half and word j+4 in its high half.
		VPUNPCKLQDQ(y(10), y(8), y(0))
		VPUNPCKHQDQ(y(10), y(8), y(1))
		VPUNPCKLQDQ(y(11), y(9), y(2))
		VPUNPCKHQDQ(y(11), y(9), y(3))
		VPUNPCKLQDQ(y(14), y(12), y(4))
		VPUNPCKHQDQ(y(14), y(12), y(5))
		VPUNPCKLQDQ(y(15), y(13), y(6))
		VPUNPCKHQDQ(y(15), y(13), y(7))
		for j := 0; j < 4; j++ {
			VPERM2I128(Imm(0x20), y(j+4), y(j), y(8))
			VPERM2I128(Imm(0x31), y(j+4), y(j), y(9))
			VMOVDQU(y(8), m.Offset((8*half+j)*32))
			VMOVDQU(y(9), m.Offset((8*half+j+4)*32))
		}
	}

	// State: v0..v7 = h, v8..v11 = IV, v12/v13 = IV ^ counter, v14/v15 = IV
	// (no finalisation flag on this path); v14 and v15 live on the stack.
	for i := 0; i < 8; i++ {
		VMOVDQU(Mem{Base: hPtr, Disp: 32 * i}, y(i))
	}
	ivp := GP64()
	LEAQ(ivSym, ivp)
	for i := 0; i < 4; i++ {
		VPBROADCASTD(Mem{Base: ivp, Disp: 4 * i}, y(8+i))
	}
	ADDQ(Imm(64), t)
	tmp := GP64()
	MOVQ(t, tmp)
	VMOVD(tmp.As32(), X15)
	VPBROADCASTD(X15, Y12)
	VPBROADCASTD(Mem{Base: ivp, Disp: 16}, Y15)
	VPXOR(Y15, Y12, Y12)
	SHRQ(Imm(32), tmp)
	VMOVD(tmp.As32(), X15)
	VPBROADCASTD(X15, Y13)
	VPBROADCASTD(Mem{Base: ivp, Disp: 20}, Y15)
	VPXOR(Y15, Y13, Y13)
	VPBROADCASTD(Mem{Base: ivp, Disp: 24}, Y15)
	VMOVDQU(Y15, v14)
	VPBROADCASTD(Mem{Base: ivp, Disp: 28}, Y15)
	VMOVDQU(Y15, v15)

	for r := 0; r < 10; r++ {
		s := sigma[r]
		g(0, 4, 8, 12, s[0], s[1], m, v14, v15, rot16, rot8)
		g(1, 5, 9, 13, s[2], s[3], m, v14, v15, rot16, rot8)
		g(2, 6, 10, 14, s[4], s[5], m, v14, v15, rot16, rot8)
		g(3, 7, 11, 15, s[6], s[7], m, v14, v15, rot16, rot8)
		g(0, 5, 10, 15, s[8], s[9], m, v14, v15, rot16, rot8)
		g(1, 6, 11, 12, s[10], s[11], m, v14, v15, rot16, rot8)
		g(2, 7, 8, 13, s[12], s[13], m, v14, v15, rot16, rot8)
		g(3, 4, 9, 14, s[14], s[15], m, v14, v15, rot16, rot8)
	}

	// h[i] ^= v[i] ^ v[i+8].
	for i := 0; i < 6; i++ {
		VPXOR(y(i), y(i+8), Y15)
		VPXOR(Mem{Base: hPtr, Disp: 32 * i}, Y15, Y15)
		VMOVDQU(Y15, Mem{Base: hPtr, Disp: 32 * i})
	}
	VMOVDQU(v14, Y15)
	VPXOR(Y6, Y15, Y15)
	VPXOR(Mem{Base: hPtr, Disp: 32 * 6}, Y15, Y15)
	VMOVDQU(Y15, Mem{Base: hPtr, Disp: 32 * 6})
	VMOVDQU(v15, Y15)
	VPXOR(Y7, Y15, Y15)
	VPXOR(Mem{Base: hPtr, Disp: 32 * 7}, Y15, Y15)
	VMOVDQU(Y15, Mem{Base: hPtr, Disp: 32 * 7})

	ADDQ(I32(512), pPtr)
	DECQ(n)
	JNZ(LabelRef("stride"))

	Label("done")
	VZEROUPPER()
	RET()
	Generate()
}

// g emits one BLAKE2s G on the vectors a, b, c, d with message words x, y.
// v14 and v15 are spilled, so a G that touches one stages it through Y14.
func g(a, b, c, d int, x, yi byte, m, v14, v15 Mem, rot16, rot8 Mem) {
	ra, rb, rc := y(a), y(b), y(c)
	rd := y(d)
	switch d {
	case 14:
		rd = Y14
		VMOVDQU(v14, rd)
	case 15:
		rd = Y14
		VMOVDQU(v15, rd)
	}
	mx := m.Offset(int(x) * 32)
	my := m.Offset(int(yi) * 32)

	VPADDD(rb, ra, ra)
	VPADDD(mx, ra, ra)
	VPXOR(ra, rd, rd)
	VPSHUFB(rot16, rd, rd)
	VPADDD(rd, rc, rc)
	VPXOR(rc, rb, rb)
	rotr(rb, 12)
	VPADDD(rb, ra, ra)
	VPADDD(my, ra, ra)
	VPXOR(ra, rd, rd)
	VPSHUFB(rot8, rd, rd)
	VPADDD(rd, rc, rc)
	VPXOR(rc, rb, rb)
	rotr(rb, 7)

	switch d {
	case 14:
		VMOVDQU(rd, v14)
	case 15:
		VMOVDQU(rd, v15)
	}
}

func rotr(r Register, n uint64) {
	VPSRLD(Imm(n), r, Y15)
	VPSLLD(Imm(32-n), r, r)
	VPOR(Y15, r, r)
}
