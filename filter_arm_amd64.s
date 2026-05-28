//go:build amd64

#include "textflag.h"

// func filterArmAVX2(buf []byte, offset int64) int
// Requires: AVX, AVX2, SSE2
TEXT ·filterArmAVX2(SB), NOSPLIT, $0-40
	MOVQ         buf_base+0(FP), AX
	MOVQ         buf_len+8(FP), CX
	MOVQ         offset+24(FP), DX
	XORQ         BX, BX
	SUBQ         $0x20, CX
	JL           done
	LEAQ         filterArmEB<>+0(SB), SI
	VPBROADCASTD (SI), Y0
	LEAQ         filterArmMask24<>+0(SB), SI
	VPBROADCASTD (SI), Y1
	LEAQ         filterArmSeq<>+0(SB), SI
	VMOVDQU      (SI), Y2

loop:
	CMPQ         BX, CX
	JG           done
	VMOVDQU      (AX)(BX*1), Y3
	VPSRLD       $0x18, Y3, Y4
	VPCMPEQD     Y0, Y4, Y4
	VPAND        Y1, Y4, Y4
	MOVQ         DX, SI
	ADDQ         BX, SI
	SHRQ         $0x02, SI
	MOVD         SI, X5
	VPBROADCASTD X5, Y5
	VPADDD       Y2, Y5, Y6
	VPAND        Y1, Y3, Y5
	VPSUBD       Y6, Y5, Y5
	VPAND        Y4, Y5, Y5
	VPANDN       Y3, Y4, Y3
	VPOR         Y5, Y3, Y3
	VMOVDQU      Y3, (AX)(BX*1)
	ADDQ         $0x20, BX
	JMP          loop

done:
	MOVQ BX, ret+32(FP)
	RET

DATA filterArmEB<>+0(SB)/4, $0x000000eb
GLOBL filterArmEB<>(SB), RODATA, $4

DATA filterArmMask24<>+0(SB)/4, $0x00ffffff
GLOBL filterArmMask24<>(SB), RODATA, $4

DATA filterArmSeq<>+0(SB)/4, $0x00000000
DATA filterArmSeq<>+4(SB)/4, $0x00000001
DATA filterArmSeq<>+8(SB)/4, $0x00000002
DATA filterArmSeq<>+12(SB)/4, $0x00000003
DATA filterArmSeq<>+16(SB)/4, $0x00000004
DATA filterArmSeq<>+20(SB)/4, $0x00000005
DATA filterArmSeq<>+24(SB)/4, $0x00000006
DATA filterArmSeq<>+28(SB)/4, $0x00000007
GLOBL filterArmSeq<>(SB), RODATA, $32
