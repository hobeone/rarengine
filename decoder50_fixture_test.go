package rarengine

import (
	"io"
	"os"
	"testing"
)

// rar5_sweep.rar is rar's own output for
//
//	rar a -ma5 -ep -s -ds -m3 -md32m -msjpg rar5_sweep.rar a_text.txt b_stored.jpg c_code.exe
//
// where a_text.txt is the concatenation of this package's *.go files (about
// 860 KB), b_stored.jpg is 4096 random bytes (stored under -msjpg) and
// c_code.exe is 200000 bytes of an x86-64 Go binary's .text section, taken
// from file offset 400000 of the section. It is small and has the shapes the
// damaged-input sweep aims at: several blocks, more than one of them carrying
// new tables, a stored member in the middle of a solid run, and a member whose
// blocks carry an x86 filter. See testdata/generate.sh.
// Mutation check: regenerate it with -m0, or with the executable member
// omitted, and the matching assertion below fails.
func TestSweepFixtureShape(t *testing.T) {
	data := fixtureBytes(t, "rar5_sweep.rar")

	byMember := blockHeaderOffsetsByMember(t, data)
	if len(byMember) < 2 {
		t.Fatalf("%d compressed members have block headers; the sweep targets at least two (text and executable)", len(byMember))
	}
	offsets := byMember[0]
	newTables := 0
	for _, off := range offsets {
		if data[off]&0x80 != 0 {
			newTables++
		}
	}
	if len(offsets) < 4 || newTables < 2 {
		t.Errorf("first compressed member: %d blocks, %d with new tables; want at least 4 and 2", len(offsets), newTables)
	}

	r := readerFor(data)
	defer r.Close() //nolint:errcheck
	r.SetWorkers(2)
	members, stored, filterPeak := 0, 0, 0
	buf := make([]byte, 32*1024)
	for {
		e, err := r.NextEntry()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}
		members++
		if e.Header.Method == 0 {
			stored++
		}
		for {
			_, rerr := e.Read(buf)
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				t.Fatalf("Read: %v", rerr)
			}
		}
	}
	blocks := pipelineBlocks(r)
	// The filter queue is drained as blocks are replayed, so sample it from a
	// serial decode of the same archive, as TestExeFixtureReachesFilterPath does.
	rs := readerFor(data)
	defer rs.Close() //nolint:errcheck
	for {
		e, err := rs.NextEntry()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("serial NextEntry: %v", err)
		}
		for {
			filterPeak = max(filterPeak, len(rs.dec50.fl))
			if _, rerr := e.Read(buf); rerr != nil {
				if rerr != io.EOF {
					t.Fatalf("serial Read: %v", rerr)
				}
				break
			}
		}
	}

	if members != 3 || stored != 1 {
		t.Errorf("%d members, %d stored; want 3 and 1", members, stored)
	}
	if blocks < 5 {
		t.Errorf("%d blocks went through the pipeline; want at least 5", blocks)
	}
	if filterPeak == 0 {
		t.Error("no filter was queued: the executable member does not reach the filter path")
	}
	t.Logf("members=%d stored=%d blocks=%d (first member %d, %d with tables) peak filters=%d",
		members, stored, blocks, len(offsets), newTables, filterPeak)
}

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
