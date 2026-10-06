package rarengine

import "unsafe"

// rarengine requires a 64-bit int: RAR5 distances reach 2^32 and decodeOffset
// accumulates them in an int. This guard fails any build where int is narrower
// than 64 bits.
var _ [unsafe.Sizeof(int(0)) - 8]struct{}
