package rarengine

import (
	"io"
	"os"
	"testing"
)

// TestExeFixtureReachesFilterPath pins the property that makes
// rar5_exe_filter.rar worth checking in. A regeneration could produce an
// archive that decodes identically but queues no filters, which every other
// test would accept while the filter path silently lost its only end-to-end
// coverage. See testdata/generate.sh.
func TestExeFixtureReachesFilterPath(t *testing.T) {
	f, err := os.Open("testdata/rar5_exe_filter.rar")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	r := NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}

	// Filters are queued during decode and popped as their blocks are reached,
	// so sample the high-water mark rather than the final depth.
	var peak int
	buf := make([]byte, 32*1024)
	for {
		if got := len(r.dec50.fl); got > peak {
			peak = got
		}
		if _, err := e.Read(buf); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("Read: %v", err)
		}
	}

	if peak == 0 {
		t.Error("fixture queued no filters: the filter path has no end-to-end coverage")
	}
	t.Logf("peak queued filters = %d", peak)
}
