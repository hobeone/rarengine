//go:build 386 || arm || mips || mipsle || ppc || s390 || sparc
// +build 386 arm mips mipsle ppc s390 sparc

package rarengine

// This file is included only on 32-bit architectures and references
// an undefined identifier to produce a clear, explicit error message.
var _ = rarengine_requires_a_64_bit_int_see_CLAUDE_md
