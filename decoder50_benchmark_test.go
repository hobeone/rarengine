package rarengine

import (
	"testing"
)

func BenchmarkFilterExecution(b *testing.B) {
	fl := make([]filterBlock, 100)
	filterBuf := make([]byte, 16)
	filterOutBuf := make([]byte, 16)
	p := make([]byte, 16)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := range 100 {
			fl[j] = filterBlock{
				start:  int64(j),
				length: 16,
				ftype:  uint8(j % 4),
				param:  5,
			}
		}

		tot := int64(0)
		activeFl := fl

		for len(activeFl) > 0 {
			f := activeFl[0]
			activeFl = activeFl[1:]

			var out []byte
			switch f.ftype {
			case 0:
				out = filterDelta(int(f.param), filterBuf, filterOutBuf)
			case 1:
				out = filterE8(0xe8, filterBuf, tot)
			case 2:
				out = filterE8(0xe9, filterBuf, tot)
			case 3:
				out = filterArm(filterBuf, tot)
			}
			tot += int64(len(out))
			copy(p, out)
		}
	}
}
