package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
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
		h, err := readBlockHeader(r)
		if err != nil {
			t.Fatalf("no file header found in %s: %v", fixture, err)
		}
		if h.Type == headerTypeFile {
			fh, err := parseFileHeader(h)
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
// fileFlagHasUnixMtime for whole-second times and records sub-second times in
// extra record 3 instead, so parsing the flag alone left ModificationTime zero
// for every archive rar actually produces -- which made IgnoreUnrarDates a
// no-op and left extracted files without their archive timestamps.
func TestParseFileHeader_ModificationTimeMatchesUnrar(t *testing.T) {
	// Asserted in UTC. The instant is what the archive records and what this
	// parser must reproduce; the rendering is not. An earlier version of this
	// test compared the local-time string `unrar lt` printed on the author's
	// machine, which passed there and failed in CI purely because CI runs in
	// UTC -- the parsed instant was identical in both.
	//
	// The values below are that same instant: `unrar lt` renders it as
	// 16:31:14 at UTC-7 and CI rendered it as 23:31:14 at UTC.
	cases := []struct {
		fixture string
		want    time.Time
	}{
		{"rar5_store.rar", time.Date(2026, 5, 17, 23, 31, 14, 684961927, time.UTC)},
		{"rar5_times.rar", time.Date(2026, 5, 17, 23, 31, 14, 684961927, time.UTC)},
		{"rar5_multi.part01.rar", time.Date(2026, 5, 17, 23, 31, 14, 685972798, time.UTC)},
	}

	for _, tc := range cases {
		got := mtimeOf(t, tc.fixture)
		if got.IsZero() {
			t.Errorf("%s: modification time is zero; the extra record was not parsed", tc.fixture)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("%s: mtime = %s; want %s",
				tc.fixture, got.UTC().Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
		}
	}
}

// timeRecord builds a file-times extra record payload.
func timeRecord(flags uint64, secs []uint32, nsecs []uint32) []byte {
	var b bytes.Buffer
	b.Write(encodeVint(flags))
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

// TestParseTimeRecord_DeclaredFieldsMustBePresent covers times the parser does
// not keep.
//
// A record declaring ctime and atime while carrying only mtime is malformed
// however little of it this parser reads. Validating just the fields it uses
// would let a header declare data it does not have and still be accepted.
func TestParseTimeRecord_DeclaredFieldsMustBePresent(t *testing.T) {
	cases := []struct {
		name string
		rec  []byte
	}{
		{
			"unix: three declared, one carried",
			timeRecord(extraTimeUnix|extraTimeMtime|extraTimeCtime|extraTimeAtime,
				[]uint32{500}, nil),
		},
		{
			"unix with nanoseconds: seconds complete, nanoseconds short",
			timeRecord(extraTimeUnix|extraTimeMtime|extraTimeCtime|extraTimeUnixNS,
				[]uint32{500, 600}, []uint32{7}),
		},
		{
			"filetime: two declared, one carried",
			append(encodeVint(extraTimeMtime|extraTimeCtime), make([]byte, 8)...),
		},
		{
			"mtime absent but ctime declared and missing",
			timeRecord(extraTimeUnix|extraTimeCtime, nil, nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fh FileHeader
			if err := parseTimeRecord(&fh, tc.rec); !errors.Is(err, ErrCorruptFileHeader) {
				t.Errorf("parseTimeRecord = %v; want ErrCorruptFileHeader", err)
			}
		})
	}
}
