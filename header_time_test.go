package rarengine

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mtimeOf walks an archive to its first file header and returns the parsed
// modification time.
func mtimeOf(t *testing.T, fixture string) time.Time {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	r := bytes.NewReader(b[8:]) // past the RAR5 signature

	for {
		h, err := ReadBlockHeader(r)
		if err != nil {
			t.Fatalf("no file header found in %s: %v", fixture, err)
		}
		if h.Type == HeaderTypeFile {
			fh, err := ParseFileHeader(h)
			if err != nil {
				t.Fatalf("parse file header: %v", err)
			}
			return fh.ModificationTime
		}
		if h.DataSize > 0 {
			if _, err := r.Seek(h.DataSize, 1); err != nil {
				t.Fatalf("seek past payload: %v", err)
			}
		}
	}
}

// TestParseFileHeader_ModificationTimeMatchesUnrar pins the times against the
// oracle's own output.
//
// Expected values are what `unrar lt` prints for these fixtures. rar only sets
// FileFlagHasUnixMtime for whole-second times and records sub-second times in
// extra record 3 instead, so parsing the flag alone left ModificationTime zero
// for every archive rar actually produces -- which made IgnoreUnrarDates a
// no-op and left extracted files without their archive timestamps.
func TestParseFileHeader_ModificationTimeMatchesUnrar(t *testing.T) {
	// Compared as the oracle's own rendering rather than as a unix instant:
	// the epoch seconds are not something to derive by hand, and writing one
	// down from memory is how the first version of this test asserted a value
	// five days from the truth while the parser was correct.
	cases := []struct {
		fixture string
		want    string // verbatim from: unrar lt <fixture>  (comma decimal separator)
	}{
		{"rar5_store.rar", "2026-05-17 16:31:14,684961927"},
		{"rar5_times.rar", "2026-05-17 16:31:14,684961927"},
		{"rar5_multi.part01.rar", "2026-05-17 16:31:14,685972798"},
	}

	for _, tc := range cases {
		got := mtimeOf(t, tc.fixture)
		if got.IsZero() {
			t.Errorf("%s: modification time is zero; the extra record was not parsed", tc.fixture)
			continue
		}
		// unrar prints in local time, which is what mtimeOf returns.
		if rendered := got.Format("2006-01-02 15:04:05,000000000"); rendered != tc.want {
			t.Errorf("%s: mtime = %s; unrar reports %s", tc.fixture, rendered, tc.want)
		}
	}
}

// timeRecord builds a file-times extra record payload.
func timeRecord(flags uint64, secs []uint32, nsecs []uint32) []byte {
	var b bytes.Buffer
	b.Write(EncodeVint(flags))
	for _, s := range secs {
		_ = binary.Write(&b, binary.LittleEndian, s)
	}
	for _, n := range nsecs {
		_ = binary.Write(&b, binary.LittleEndian, n)
	}
	return b.Bytes()
}

// TestParseTimeRecord_NanosecondsFollowAllSeconds pins the layout detail that
// is easiest to get wrong.
//
// Every present time's seconds are stored before any of the nanoseconds, so
// the mtime nanosecond field sits after the ctime and atime seconds rather
// than immediately after its own. Reading the field next to mtime's seconds
// yields ctime's seconds interpreted as nanoseconds -- which for a real
// archive is a plausible-looking sub-second value, not an obvious failure.
func TestParseTimeRecord_NanosecondsFollowAllSeconds(t *testing.T) {
	const (
		mSec, cSec, aSec = 1000, 2000, 3000
		mNs, cNs, aNs    = 111, 222, 333
	)
	rec := timeRecord(extraTimeUnix|extraTimeMtime|extraTimeCtime|extraTimeAtime|extraTimeUnixNS,
		[]uint32{mSec, cSec, aSec}, []uint32{mNs, cNs, aNs})

	var fh FileHeader
	if err := parseTimeRecord(&fh, rec); err != nil {
		t.Fatalf("parseTimeRecord: %v", err)
	}
	if want := time.Unix(mSec, mNs); !fh.ModificationTime.Equal(want) {
		t.Errorf("mtime = %v (unix %d.%09d); want %v -- the nanosecond field was read from the "+
			"wrong offset", fh.ModificationTime, fh.ModificationTime.Unix(),
			fh.ModificationTime.Nanosecond(), want)
	}
}

// TestParseTimeRecord_Rejects covers the shapes an archive can choose that the
// straight-line read would trust.
func TestParseTimeRecord_Rejects(t *testing.T) {
	t.Run("mtime absent leaves the field zero", func(t *testing.T) {
		// Only ctime present: its seconds sit where mtime's would, so a parser
		// that does not check the flag reports ctime as the modification time.
		rec := timeRecord(extraTimeUnix|extraTimeCtime, []uint32{9999}, nil)
		var fh FileHeader
		if err := parseTimeRecord(&fh, rec); err != nil {
			t.Fatalf("parseTimeRecord: %v", err)
		}
		if !fh.ModificationTime.IsZero() {
			t.Errorf("mtime = %v; want zero, the record carries no modification time",
				fh.ModificationTime)
		}
	})

	t.Run("nanoseconds at or beyond a second are ignored", func(t *testing.T) {
		rec := timeRecord(extraTimeUnix|extraTimeMtime|extraTimeUnixNS,
			[]uint32{500}, []uint32{2_000_000_000})
		var fh FileHeader
		if err := parseTimeRecord(&fh, rec); err != nil {
			t.Fatalf("parseTimeRecord: %v", err)
		}
		if want := time.Unix(500, 0); !fh.ModificationTime.Equal(want) {
			t.Errorf("mtime = %v; want %v -- an out-of-range nanosecond field must not roll "+
				"the time into a different second", fh.ModificationTime, want)
		}
	})

	t.Run("truncated record is refused", func(t *testing.T) {
		rec := timeRecord(extraTimeUnix|extraTimeMtime|extraTimeUnixNS, []uint32{500}, nil)
		var fh FileHeader
		if err := parseTimeRecord(&fh, rec); err == nil {
			t.Error("a record promising a nanosecond field it does not carry was accepted")
		}
	})
}
