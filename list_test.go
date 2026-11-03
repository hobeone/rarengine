package rarengine

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// listNames ranges over ListVolume and returns every yielded name, failing on
// a yielded error.
func listNames(t *testing.T, data []byte) []string {
	t.Helper()
	var names []string
	for fh, err := range ListVolume(bytes.NewReader(data)) {
		if err != nil {
			t.Fatalf("ListVolume yielded %v after %v", err, names)
		}
		names = append(names, fh.Name)
	}
	return names
}

// The case ListVolume exists for: a later volume that opens with the tail of
// an earlier member and then starts a new one. Extraction refuses it; listing
// reports the member it starts and nothing else. The committed later-volume
// fixtures hold only a continuation, so a ListVolume that yielded nothing
// would pass against them -- these are built so that it cannot.
func TestListVolumeReportsWhatALaterVolumeStarts(t *testing.T) {
	cont := []byte("tail of a member begun earlier")
	rar4Cont := rar4File(rar4FileSpec{
		Name:    []byte("old.bin"),
		Flags:   0x8000 | rar4FileSplitBefore,
		PackLow: uint32(len(cont)), UnpLow: uint32(len(cont)),
		UnpVer: 29, Method: 0x30,
	})
	newContent := []byte("starts here")
	rar4New := rar4File(rar4FileSpec{
		Name:    []byte("new.bin"),
		Flags:   0x8000,
		PackLow: uint32(len(newContent)), UnpLow: uint32(len(newContent)),
		UnpVer: 29, Method: 0x30,
	})

	cases := []struct {
		name   string
		volume []byte
	}{
		// Both S1 (volume number 1) and S2 (leading continuation) would
		// refuse this volume under NextEntry.
		{"rar5", append(rar5VolumeHeader(arcFlagMultiVol, 1), slices.Concat(
			rar5Member(t, memberSpec{name: "old.bin", content: string(cont), notFirst: true}),
			rar5Member(t, memberSpec{name: "new.bin", content: string(newContent), withCRC: true}),
		)...)},
		// RAR4 has no S1: S2 alone would refuse it.
		{"rar4", rar4Volume(rar4MainVolume, rar4Cont, cont, rar4New, newContent)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := traverse(t, readerFor(tc.volume))
			if !errors.Is(err, ErrNotFirstVolume) {
				t.Fatalf("NextEntry over the volume = %v, want ErrNotFirstVolume (fixture no longer exercises the suppression)", err)
			}
			if got := listNames(t, tc.volume); !slices.Equal(got, []string{"new.bin"}) {
				t.Fatalf("ListVolume = %v, want [new.bin]", got)
			}
		})
	}
}

// A first volume lists the members it starts, matching what extraction of the
// whole set produces from it.
func TestListVolumeOnAFirstVolume(t *testing.T) {
	got := listNames(t, fixtureBytes(t, "rar5_blake2_store_multi.part1.rar"))
	want, err := traverse(t, NewReader(testdataVolumes(t,
		"rar5_blake2_store_multi.part1.rar",
		"rar5_blake2_store_multi.part2.rar",
		"rar5_blake2_store_multi.part3.rar",
		"rar5_blake2_store_multi.part4.rar",
	)))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("extracting the set: %v", err)
	}
	if len(got) == 0 || !slices.Equal(got, want) {
		t.Fatalf("ListVolume(part1) = %v, want %v", got, want)
	}
}

// Breaking out of the range ends the listing: the iterator must not call
// yield again, which the range-over-func runtime turns into a panic.
func TestListVolumeStopsOnBreak(t *testing.T) {
	vol := rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "a.bin", content: "one", withCRC: true}),
		rar5Member(t, memberSpec{name: "b.bin", content: "two", withCRC: true}),
	)
	var seen []string
	for fh, err := range ListVolume(bytes.NewReader(vol)) {
		if err != nil {
			t.Fatalf("ListVolume: %v", err)
		}
		seen = append(seen, fh.Name)
		break
	}
	if !slices.Equal(seen, []string{"a.bin"}) {
		t.Fatalf("seen = %v, want [a.bin]", seen)
	}
}

// A member refused after its name was decoded is still a member this volume
// starts, so it is listed by name -- with its refusal beside it, since the
// field it was refused for holds the value the archive declared -- and the
// listing goes on to the member behind it.
func TestListVolumeYieldsAMemberRefusedByNameWithItsRefusal(t *testing.T) {
	vol := rar5Archive(t, false,
		memberWithNegativeSize(t, "refused.bin", "secret", false),
		rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
	)
	type listed struct {
		name string
		err  error
	}
	var got []listed
	for fh, err := range ListVolume(bytes.NewReader(vol)) {
		if fh == nil {
			t.Fatalf("archive-level error %v after %v", err, got)
		}
		got = append(got, listed{fh.Name, err})
	}
	if len(got) != 2 || got[0].name != "refused.bin" || got[1].name != "after.bin" {
		t.Fatalf("listed %v, want refused.bin then after.bin", got)
	}
	if !errors.Is(got[0].err, ErrCorruptFileHeader) {
		t.Errorf("refused.bin yielded with %v, want its ErrCorruptFileHeader refusal", got[0].err)
	}
	if got[1].err != nil {
		t.Errorf("after.bin yielded with %v, want nil", got[1].err)
	}
}

// A RAR 1.5-4.x symlink's target is its payload, which listing does not read,
// so it is listed as an ordinary member with LinkType unset.
func TestListVolumeDoesNotReadARAR4SymlinkTarget(t *testing.T) {
	links := 0
	for fh, err := range ListVolume(bytes.NewReader(fixtureBytes(t, "rar4_symlink.rar"))) {
		if err != nil {
			t.Fatalf("ListVolume: %v", err)
		}
		if strings.HasPrefix(fh.Name, "link_") {
			links++
			if fh.LinkType != LinkNone || fh.LinkTarget != "" {
				t.Fatalf("%s: LinkType %v LinkTarget %q, want neither read", fh.Name, fh.LinkType, fh.LinkTarget)
			}
		}
	}
	if links != 3 {
		t.Fatalf("listed %d link_ members, want the fixture's 3", links)
	}
}

// A traversal error is yielded once, unchanged, with a nil header.
func TestListVolumeYieldsTraversalErrors(t *testing.T) {
	var errs []error
	for fh, err := range ListVolume(bytes.NewReader(fixtureBytes(t, "rar5_enchdr_multi.part2.rar"))) {
		if fh != nil {
			t.Fatalf("yielded header %q from a header-encrypted volume with no password", fh.Name)
		}
		errs = append(errs, err)
	}
	if len(errs) != 1 || !errors.Is(errs[0], ErrPasswordRequired) {
		t.Fatalf("errors = %v, want exactly one ErrPasswordRequired", errs)
	}
}

// Listing decodes nothing, so it reserves no window: a member declaring a
// 64 MiB dictionary, and a solid volume whose members extraction would have
// to decode to abandon, both leave the window at its minimum with no backing.
// This drives the listing traversal directly, because ListVolume's Reader is
// not reachable from outside it.
func TestListingReservesNoWindow(t *testing.T) {
	for _, fixture := range []string{"rar5_dict_64m.rar", "rar5_solid_multi_qo.part1.rar"} {
		t.Run(fixture, func(t *testing.T) {
			r := NewReader(fileVolumesOf(t, filepath.Join("testdata", fixture)))
			defer r.Close() //nolint:errcheck
			r.listing = true
			var names []string
			var closeErrs []error
			var err error
			for {
				var e *Entry
				if e, err = r.NextEntry(); err != nil {
					break
				}
				names = append(names, e.Header.Name)
				closeErrs = append(closeErrs, e.Close())
			}
			if len(names) == 0 {
				t.Fatalf("listed nothing (%v), want the volume's members", err)
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("listing ended with %v", err)
			}
			if r.win.size != minWindowSize || r.win.backing != nil {
				t.Fatalf("window = %d bytes, backing %v; want the %d minimum with no reservation",
					r.win.size, r.win.backing != nil, minWindowSize)
			}
			for i, cerr := range closeErrs {
				if !errors.Is(cerr, errListedOnly) {
					t.Fatalf("listed entry %s Close = %v, want errListedOnly", names[i], cerr)
				}
			}
		})
	}
}
