//go:build amd64

#include "textflag.h"

// func filterE8ScanAVX2(buf []byte, c byte) int
// Requires: AVX, AVX2, SSE2
TEXT ·filterE8ScanAVX2(SB), NOSPLIT, $0-40
	MOVQ         buf_base+0(FP), AX
	MOVQ         buf_len+8(FP), CX
	MOVBLZX      c+24(FP), DX
	XORQ         BX, BX
	MOVD         DX, X0
	VPBROADCASTB X0, Y0
	LEAQ         filterE8Constant<>+0(SB), DX
	VPBROADCASTB (DX), Y1
	SUBQ         $0x20, CX

loop32:
	CMPQ      BX, CX
	JG        scalar
	VMOVDQU   (AX)(BX*1), Y2
	VPCMPEQB  Y1, Y2, Y3
	VPCMPEQB  Y0, Y2, Y2
	VPOR      Y3, Y2, Y2
	VPMOVMSKB Y2, DX
	CMPL      DX, $0x00
	JNE       found32
	ADDQ      $0x20, BX
	JMP       loop32

found32:
	MOVL DX, AX
	BSFQ AX, SI
	MOVQ BX, AX
	ADDQ SI, AX
	MOVQ AX, ret+32(FP)
	RET

scalar:
	MOVQ BX, ret+32(FP)
	RET

DATA filterE8Constant<>+0(SB)/1, $0xe8
GLOBL filterE8Constant<>(SB), RODATA, $1
