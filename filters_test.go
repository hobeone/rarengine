package rarengine

import (
	"bytes"
	"testing"
)

func TestFilterDelta(t *testing.T) {
	buf := []byte{1, 2, 3, 4}
	got := FilterDelta(2, buf)
	expected := []byte{255, 253, 253, 249}
	if !bytes.Equal(got, expected) {
		t.Errorf("expected %x, got %x", expected, got)
	}
}

func TestFilterArm(t *testing.T) {
	sizes := []int{0, 3, 4, 15, 32, 35, 64, 100, 1024, 1024 + 13}
	for _, size := range sizes {
		buf1 := make([]byte, size)
		buf2 := make([]byte, size)
		for i := range size {
			if i%4 == 3 && i%8 == 3 {
				buf1[i] = 0xeb
			} else {
				buf1[i] = byte(i * 17)
			}
		}
		copy(buf2, buf1)

		offset := int64(12345)

		// 1. Run generic/scalar (SIMD disabled)
		savedSIMD := filterArmSIMD
		filterArmSIMD = nil
		gotGeneric := FilterArm(buf1, offset)

		// 2. Run SIMD (restored)
		filterArmSIMD = savedSIMD
		gotSIMD := FilterArm(buf2, offset)

		if !bytes.Equal(gotGeneric, gotSIMD) {
			t.Fatalf("size %d: SIMD and Generic outputs differ", size)
		}
	}
}

func TestFilterE8(t *testing.T) {
	sizes := []int{0, 4, 5, 10, 31, 32, 33, 64, 100, 1024, 1024 + 17}
	for _, size := range sizes {
		for _, c := range []byte{0xe8, 0xe9} {
			for _, v5 := range []bool{false, true} {
				buf1 := make([]byte, size)
				for i := range size {
					if i%17 == 3 {
						buf1[i] = 0xe8
					} else if i%17 == 7 {
						buf1[i] = 0xe9
					} else {
						buf1[i] = byte(i * 13)
					}
				}
				buf2 := make([]byte, size)
				copy(buf2, buf1)

				// 1. Run generic/scalar (SIMD disabled)
				savedSIMD := filterE8ScanSIMD
				filterE8ScanSIMD = nil
				gotGeneric := FilterE8(c, v5, buf1, 1000)

				// 2. Run SIMD (restored)
				filterE8ScanSIMD = savedSIMD
				gotSIMD := FilterE8(c, v5, buf2, 1000)

				if !bytes.Equal(gotGeneric, gotSIMD) {
					t.Fatalf("size=%d, c=%x, v5=%v: SIMD result does not match Generic", size, c, v5)
				}
			}
		}
	}
}
