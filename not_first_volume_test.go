package rarengine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Tests for ErrNotFirstVolume: a volume stream that does not open at the first
// volume of its set is refused, rather than skipping the leading continuation
// and reporting a clean io.EOF after no members -- which a caller looping until
// io.EOF reads as "the set extracted, and held nothing".
//
// Two pieces of evidence reach the verdict. S1 is a RAR5 first-received
// archive header declaring a volume number above 0; it is the only signal for
// a RAR5 middle volume that opens on a member boundary. S2 is a first file
// block that continues a member from an earlier volume, read from the block's
// own flags, so it covers RAR4 and a header that fails to parse.

const (
	s1Evidence = "the stream starts at volume"
	s2Evidence = "its first file block continues a file from an earlier volume"
)

// testdataVolumes feeds the named testdata fixtures in order.
func testdataVolumes(t *testing.T, names ...string) <-chan io.ReadCloser {
	t.Helper()
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = filepath.Join("testdata", n)
	}
	return fileVolumesOf(t, paths...)
}

// traverse reads every entry of r to the end, closing each, and returns the
// error that ended the traversal plus the names of the members it produced.
func traverse(t *testing.T, r *Reader) ([]string, error) {
	t.Helper()
	var names []string
	for {
		e, err := r.NextEntry()
		if err != nil {
			return names, err
		}
		names = append(names, e.Header.Name)
		if _, err := io.Copy(io.Discard, e); err != nil {
			t.Fatalf("reading %s: %v", e.Header.Name, err)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("closing %s: %v", e.Header.Name, err)
		}
	}
}

// drain reads every member to its end, tolerating member failures, and
// returns each member's Close verdict and the error that ended the traversal.
func drain(r *Reader) ([]error, error) {
	var verdicts []error
	for {
		e, err := r.NextEntry()
		if err != nil {
			return verdicts, err
		}
		_, _ = io.Copy(io.Discard, e)
		verdicts = append(verdicts, e.Close())
	}
}

// assertRefusedBeforeAnyMember traverses volumes and requires the traversal to
// produce no member and end with ErrNotFirstVolume carrying evidence.
func assertRefusedBeforeAnyMember(t *testing.T, volumes <-chan io.ReadCloser, evidence string) {
	t.Helper()
	r := NewReader(volumes)
	defer r.Close() //nolint:errcheck
	names, err := traverse(t, r)
	if len(names) != 0 {
		t.Fatalf("traversal produced %v before refusing, want nothing", names)
	}
	assertNotFirstVolume(t, err, evidence)
}

// assertNotFirstVolume requires err to be ErrNotFirstVolume carrying evidence.
func assertNotFirstVolume(t *testing.T, err error, evidence string) {
	t.Helper()
	if !errors.Is(err, ErrNotFirstVolume) {
		t.Fatalf("error = %v, want ErrNotFirstVolume", err)
	}
	if !strings.Contains(err.Error(), evidence) {
		t.Fatalf("error = %q, want it to name the evidence %q", err, evidence)
	}
}

// Callers treat io.EOF and ErrNoNextVolume as a clean end, so matching either
// would bring the false success back with no other change.
func TestErrNotFirstVolumeIsNotACleanEnd(t *testing.T) {
	if errors.Is(ErrNotFirstVolume, io.EOF) {
		t.Fatal("errors.Is(ErrNotFirstVolume, io.EOF) = true, want false")
	}
	if errors.Is(ErrNotFirstVolume, ErrNoNextVolume) {
		t.Fatal("errors.Is(ErrNotFirstVolume, ErrNoNextVolume) = true, want false")
	}
}

// Real rar output, fed from a later volume. Each RAR5 volume after the first
// declares its number, so S1 decides before any file block is read.
func TestStreamFromALaterVolumeIsRefused(t *testing.T) {
	cases := []struct {
		name     string
		volumes  []string
		evidence string
	}{
		{"rar5 store part2 alone", []string{"rar5_blake2_store_multi.part2.rar"}, s1Evidence + " 2"},
		{"rar5 store part2..4", []string{
			"rar5_blake2_store_multi.part2.rar",
			"rar5_blake2_store_multi.part3.rar",
			"rar5_blake2_store_multi.part4.rar",
		}, s1Evidence + " 2"},
		{"rar5 compressed part03 alone", []string{"rar5_blake2_comp_multi.part03.rar"}, s1Evidence + " 3"},
		// RAR 1.5-4.x keeps volume numbers in the end header, so S2 is the
		// only evidence there.
		{"rar4 .r00 alone", []string{"rar4_store_multi.r00"}, s2Evidence},
		{"rar4 .r00 and .r01", []string{"rar4_store_multi.r00", "rar4_store_multi.r01"}, s2Evidence},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRefusedBeforeAnyMember(t, testdataVolumes(t, tc.volumes...), tc.evidence)
		})
	}
}

// The verdict latches like every archive-level error: a caller that retries
// NextEntry gets the refusal again, never a clean io.EOF.
func TestNotFirstVolumeRefusalLatches(t *testing.T) {
	r := NewReader(testdataVolumes(t, "rar5_blake2_store_multi.part2.rar"))
	defer r.Close() //nolint:errcheck
	_, first := r.NextEntry()
	assertNotFirstVolume(t, first, s1Evidence)
	_, second := r.NextEntry()
	if second == nil || second.Error() != first.Error() {
		t.Fatalf("second NextEntry = %v, want the latched %v", second, first)
	}
}

// Reset starts a new traversal, so both pieces of evidence start over: a
// full set read after a refusal extracts, and a later volume read after a
// full set is refused again.
func TestResetStartsTheFirstVolumeEvidenceOver(t *testing.T) {
	full := []string{
		"rar5_blake2_store_multi.part1.rar",
		"rar5_blake2_store_multi.part2.rar",
		"rar5_blake2_store_multi.part3.rar",
		"rar5_blake2_store_multi.part4.rar",
	}

	r := NewReader(testdataVolumes(t, "rar5_blake2_store_multi.part3.rar"))
	defer r.Close() //nolint:errcheck
	_, err := traverse(t, r)
	assertNotFirstVolume(t, err, s1Evidence)

	r.Reset(testdataVolumes(t, full...))
	names, err := traverse(t, r)
	if !errors.Is(err, io.EOF) || len(names) == 0 {
		t.Fatalf("full set after Reset = %v, %v; want its members then io.EOF", names, err)
	}

	r.Reset(testdataVolumes(t, "rar5_blake2_store_multi.part3.rar"))
	_, err = traverse(t, r)
	assertNotFirstVolume(t, err, s1Evidence)

	// RAR4: the S2 evidence (fileSeen) must start over as well. A full set
	// sets it; a following .r00 must still be refused.
	r.Reset(testdataVolumes(t, "rar4_store_multi.rar", "rar4_store_multi.r00", "rar4_store_multi.r01"))
	if names, err := traverse(t, r); !errors.Is(err, io.EOF) || len(names) == 0 {
		t.Fatalf("rar4 full set after Reset = %v, %v; want its members then io.EOF", names, err)
	}
	r.Reset(testdataVolumes(t, "rar4_store_multi.r00"))
	_, err = traverse(t, r)
	assertNotFirstVolume(t, err, s2Evidence)

	// The end-header evidence (lateNotFirst, endNumberSeen) starts over too: a
	// refusal does not outlive its traversal, and a header seen in one does
	// not stop the next from being judged.
	boundary := rar4NumberedVolume(1, true, rar4StoredPart("new.bin", 0, "abcd", "abcd"))
	first := rar4NumberedVolume(0, true, rar4StoredPart("a.bin", 0, "abcd", "abcd"))
	r.Reset(volumesOf(boundary))
	_, err = traverse(t, r)
	assertNotFirstVolume(t, err, s3Evidence)
	r.Reset(volumesOf(first))
	if _, err := traverse(t, r); !errors.Is(err, io.EOF) {
		t.Fatalf("first volume after a RAR4 end-header refusal = %v, want io.EOF", err)
	}
	r.Reset(volumesOf(boundary))
	_, err = traverse(t, r)
	assertNotFirstVolume(t, err, s3Evidence)

	// So does memberFailed: a member that failed in one traversal does not
	// withhold the end-header evidence reached through the next one's splice.
	r.Reset(volumesOf(boundary, rar4NumberedVolume(2, true, rar4StoredPart("x.bin", 0, "abcd", "abcx"))))
	if verdicts, _ := drain(r); len(verdicts) != 2 || verdicts[1] == nil {
		t.Fatalf("member verdicts = %v, want x.bin to fail", verdicts)
	}
	r.Reset(volumesOf(
		rar4NumberedVolume(1, true, rar4StoredPart("a.bin", rar4FileSplitAfter, "ab", "abcd")),
		rar4NumberedVolume(2, true, rar4StoredPart("a.bin", rar4FileSplitBefore, "cd", "abcd"))))
	_, err = traverse(t, r)
	assertNotFirstVolume(t, err, s3Evidence+" 2")
}

// In the first stream no volume can be missing before the end header, so a
// member that failed there does not withhold the evidence.
func TestRAR4FirstStreamEndHeaderIsEvidenceAfterAFailedMember(t *testing.T) {
	vol := rar4NumberedVolume(1, true, rar4StoredPart("bad.bin", 0, "abcd", "abcx"))
	r := NewReader(volumesOf(vol))
	defer r.Close() //nolint:errcheck
	verdicts, err := drain(r)
	if len(verdicts) != 1 || verdicts[0] == nil {
		t.Fatalf("member verdicts = %v, want bad.bin to fail", verdicts)
	}
	assertNotFirstVolume(t, err, s3Evidence+" 2")
}

// A header-encrypted later volume: with the password its decrypted archive
// header is what S1 reads; without one, the volume cannot be read at all and
// that is what is reported. The ordering is the point -- an archive that
// cannot be decrypted is not claimed to be a middle volume.
func TestHeaderEncryptedLaterVolume(t *testing.T) {
	r := NewReader(testdataVolumes(t, "rar5_enchdr_multi.part2.rar"))
	defer r.Close() //nolint:errcheck
	r.SetPasswords([]string{"secret"})
	_, err := r.NextEntry()
	assertNotFirstVolume(t, err, s1Evidence+" 2")

	r.Reset(testdataVolumes(t, "rar5_enchdr_multi.part2.rar"))
	r.SetPasswords(nil)
	_, err = r.NextEntry()
	if !errors.Is(err, ErrPasswordRequired) || errors.Is(err, ErrNotFirstVolume) {
		t.Fatalf("without the password: %v, want ErrPasswordRequired alone", err)
	}
}

// A first volume cut inside its signature is damage, recorded and skipped, and
// the next volume is then the first one READ -- but not the first one
// received. The traversal must report the damage, not claim the set started
// mid-way: volIndex counts the damaged volume, and S2 stands down once damage
// is recorded.
func TestDamagedFirstVolumeReportsTheDamage(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
	}{
		{"rar5", []string{
			"rar5_blake2_store_multi.part1.rar",
			"rar5_blake2_store_multi.part2.rar",
			"rar5_blake2_store_multi.part3.rar",
			"rar5_blake2_store_multi.part4.rar",
		}},
		{"rar4", []string{"rar4_store_multi.rar", "rar4_store_multi.r00", "rar4_store_multi.r01"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := make([][]byte, len(tc.parts))
			for i, n := range tc.parts {
				parts[i] = fixtureBytes(t, n)
			}
			parts[0] = parts[0][:5] // below the shortest (RAR 1.5-4.x, 7-byte) signature
			r := NewReader(volumesOf(parts...))
			defer r.Close() //nolint:errcheck
			_, err := traverse(t, r)
			if !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrNotFirstVolume) {
				t.Fatalf("traversal ended with %v, want the first volume's damage (io.ErrUnexpectedEOF) and not ErrNotFirstVolume", err)
			}
		})
	}
}

// A first file block that continues an earlier member is refused even when
// its header fails to parse. S2 reads the block's own flags before
// parseFileHeader runs, so the parse-failure arm, which skips a header it
// cannot name, never sees it.
func TestLeadingContinuationThatFailsToParseIsRefused(t *testing.T) {
	rar4Bad := rar4File(rar4FileSpec{
		Name:   []byte("cont.bin"),
		Flags:  0x8000 | rar4FileSplitBefore,
		UnpVer: 29,
		Method: 0x99, // outside 0x30-0x35: ErrCorruptFileHeader after the name
	})
	cases := []struct {
		name   string
		stream []byte
	}{
		{"rar5 bad encryption record", rar5Archive(t, false,
			memberWithEncVersion(t, "cont.enc", "secret", 1, true),
			rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
		)},
		{"rar5 name out of bounds", rar5Archive(t, false,
			rar5Member(t, memberSpec{name: "cont.bin", content: "x", notFirst: true, badName: true}),
			rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
		)},
		{"rar4 bad method", rar4Volume(rar4MainVolume, rar4Bad)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRefusedBeforeAnyMember(t, volumesOf(tc.stream), s2Evidence)
		})
	}
}

// S1 without S2: a RAR5 middle volume whose first block STARTS a member. No
// continuation is there to see, so the archive header's volume number is the
// only evidence. The fixtures above cannot pin this, because each real later
// volume also opens with a continuation.
func TestLaterVolumeOnAMemberBoundaryIsRefused(t *testing.T) {
	stream := append(rar5VolumeHeader(arcFlagMultiVol, 1),
		rar5Member(t, memberSpec{name: "new.bin", content: "starts here", withCRC: true})...)
	assertRefusedBeforeAnyMember(t, volumesOf(stream), s1Evidence+" 2")
}

const s3Evidence = "its end headers number it from volume"

// rar4NumberedVolume is one RAR 1.5-4.x volume of a set, as RAR 3.0 and later
// write it: blocks between a main header flagged as a volume and an end header
// declaring volNum. withCRC also writes the end header's data CRC ahead of the
// number, which moves where the number sits.
func rar4NumberedVolume(volNum uint16, withCRC bool, blocks ...[]byte) []byte {
	endFlags := uint16(0x4000 | rar4EndVolNumber)
	var body []byte
	if withCRC {
		endFlags |= rar4EndDataCRC
		body = append(body, 0xde, 0xad, 0xbe, 0xef)
	}
	body = binary.LittleEndian.AppendUint16(body, volNum)
	out := append(append([]byte{}, rar4Sig...), rar4MainHeader(rar4MainVolume)...)
	for _, b := range blocks {
		out = append(out, b...)
	}
	return append(out, rar4Block(0x7b, endFlags, body)...)
}

// rar4StoredPart is a stored member, or one part of a split one: content is
// this part's payload and whole is the member's full content, whose CRC and
// size every part declares.
func rar4StoredPart(name string, splitFlags uint16, content, whole string) []byte {
	return append(rar4File(rar4FileSpec{
		Name: []byte(name), Flags: rar4LongBlock | 0x20 | splitFlags,
		PackLow: uint32(len(content)), UnpLow: uint32(len(whole)),
		HostOS: 3, CRC: crc32.ChecksumIEEE([]byte(whole)), UnpVer: 20, Method: 0x30, Attr: 0x81a4,
	}), content...)
}

// A RAR 1.5-4.x later volume that opens on a member boundary has no
// continuation and no volume number in its main header, so nothing refuses it
// before its members are read. Its end header does number it, and that is
// reported in io.EOF's place: the members it starts are delivered, and the
// traversal still does not end as if the set were complete.
func TestRAR4LaterVolumeOnAMemberBoundaryEndsInTheRefusal(t *testing.T) {
	for _, withCRC := range []bool{true, false} {
		t.Run(fmt.Sprintf("data CRC %v", withCRC), func(t *testing.T) {
			vol := rar4NumberedVolume(1, withCRC, rar4StoredPart("new.bin", 0, "abcd", "abcd"))
			names, err := traverse(t, NewReader(volumesOf(vol)))
			if !slices.Equal(names, []string{"new.bin"}) {
				t.Fatalf("members = %v, want [new.bin]", names)
			}
			assertNotFirstVolume(t, err, s3Evidence+" 2")
		})
	}
}

// Read from its first volume, a numbered RAR4 set ends cleanly: volume 0's
// end header is no evidence, and volume 1's is read after another volume was
// received, through the splice.
func TestRAR4NumberedSetFromTheStartEndsCleanly(t *testing.T) {
	v1 := rar4NumberedVolume(0, true, rar4StoredPart("a.bin", rar4FileSplitAfter, "ab", "abcd"))
	v2 := rar4NumberedVolume(1, true, rar4StoredPart("a.bin", rar4FileSplitBefore, "cd", "abcd"))
	names, err := traverse(t, NewReader(volumesOf(v1, v2)))
	if !slices.Equal(names, []string{"a.bin"}) || !errors.Is(err, io.EOF) {
		t.Fatalf("traversal = %v, %v; want [a.bin] then io.EOF", names, err)
	}
}

// When the first volume's last member continues into the next volume, the
// splice opens that volume without reading the end header behind the member.
// The next volume's end header is then the first numbered one: volume 3 read
// as the second stream says the stream started at volume 2. The member being
// spliced completes, and the refusal arrives in io.EOF's place.
func TestRAR4EndHeaderEvidenceReachedThroughTheSplice(t *testing.T) {
	v1 := rar4NumberedVolume(1, true,
		rar4StoredPart("x.bin", 0, "whole", "whole"),
		rar4StoredPart("a.bin", rar4FileSplitAfter, "ab", "abcd"))
	v2 := rar4NumberedVolume(2, true, rar4StoredPart("a.bin", rar4FileSplitBefore, "cd", "abcd"))
	names, err := traverse(t, NewReader(volumesOf(v1, v2)))
	if !slices.Equal(names, []string{"x.bin", "a.bin"}) {
		t.Fatalf("members = %v, want [x.bin a.bin] delivered", names)
	}
	assertNotFirstVolume(t, err, s3Evidence+" 2")
}

// A set fed from its first volume with a volume missing or misordered inside
// a spliced member is not a late start. The member spanning the gap fails, and
// the end header read behind it, which numbers a later volume, is not evidence:
// the traversal ends with io.EOF and the member's own verdict.
func TestRAR4EndHeaderAfterAFailedSpliceIsNotEvidence(t *testing.T) {
	v1 := rar4NumberedVolume(0, true, rar4StoredPart("a.bin", rar4FileSplitAfter, "ab", "abcdef"))
	v2 := rar4NumberedVolume(1, true, rar4StoredPart("a.bin", rar4FileSplitBefore|rar4FileSplitAfter, "cd", "abcdef"))
	v3 := rar4NumberedVolume(2, true, rar4StoredPart("a.bin", rar4FileSplitBefore, "ef", "abcdef"))
	cases := []struct {
		name    string
		volumes [][]byte
	}{
		{"volume 2 missing", [][]byte{v1, v3}},
		{"volumes 2 and 3 swapped", [][]byte{v1, v3, v2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(volumesOf(tc.volumes...))
			defer r.Close() //nolint:errcheck
			verdicts, err := drain(r)
			if !errors.Is(err, io.EOF) {
				t.Fatalf("traversal ended with %v after member verdicts %v, want io.EOF", err, verdicts)
			}
			if len(verdicts) == 0 || verdicts[0] == nil {
				t.Fatalf("member verdicts = %v, want a.bin to fail", verdicts)
			}
		})
	}
}

// An end header the splice reaches while a member is still in progress is
// not judged: that member's verdict is not in yet. Here a numbered volume with
// no file blocks sits inside a member that then verifies clean.
func TestRAR4EndHeaderReachedMidMemberIsNotEvidence(t *testing.T) {
	v1 := rar4NumberedVolume(0, true, rar4StoredPart("a.bin", rar4FileSplitAfter, "ab", "abcd"))
	empty := rar4NumberedVolume(5, true)
	v2 := rar4NumberedVolume(1, true, rar4StoredPart("a.bin", rar4FileSplitBefore, "cd", "abcd"))
	r := NewReader(volumesOf(v1, empty, v2))
	defer r.Close() //nolint:errcheck
	verdicts, err := drain(r)
	if len(verdicts) != 1 || verdicts[0] != nil || !errors.Is(err, io.EOF) {
		t.Fatalf("traversal = verdicts %v, %v; want a.bin clean then io.EOF", verdicts, err)
	}
}

// The volume number is attacker-chosen, up to MaxInt. The message names the
// 1-based volume without wrapping negative.
func TestLaterVolumeAtTheLargestVolumeNumberNamesItUnwrapped(t *testing.T) {
	stream := append(rar5VolumeHeader(arcFlagMultiVol, math.MaxInt),
		rar5Member(t, memberSpec{name: "new.bin", content: "x", withCRC: true})...)
	assertRefusedBeforeAnyMember(t, volumesOf(stream), s1Evidence+" 9223372036854775808")
}

// S1's other conjuncts: volume number 0 is the first volume, and a volume
// number on an archive that does not declare itself part of a set is not
// evidence of one. Both extract.
func TestFirstVolumeHeadersAreNotRefused(t *testing.T) {
	member := rar5Member(t, memberSpec{name: "a.bin", content: "payload", withCRC: true})
	cases := []struct {
		name   string
		header []byte
	}{
		{"multi-volume, volume number 0", rar5VolumeHeader(arcFlagMultiVol, 0)},
		{"volume number 1, not multi-volume", rar5VolumeHeader(0, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(volumesOf(append(append([]byte{}, tc.header...), member...)))
			defer r.Close() //nolint:errcheck
			names, err := traverse(t, r)
			if len(names) != 1 || names[0] != "a.bin" || !errors.Is(err, io.EOF) {
				t.Fatalf("traversal = %v, %v; want [a.bin] then io.EOF", names, err)
			}
		})
	}
}

// S1 reads only the first volume received. The second volume of a set read
// from the start declares volume number 1 and must not trip it.
func TestLaterVolumeHeaderInsideASetIsNotEvidence(t *testing.T) {
	part1 := append(rar5VolumeHeader(arcFlagMultiVol, 0),
		rar5Member(t, memberSpec{name: "a.bin", content: "first", withCRC: true})...)
	part2 := append(rar5VolumeHeader(arcFlagMultiVol, 1),
		rar5Member(t, memberSpec{name: "b.bin", content: "second", withCRC: true})...)
	r := NewReader(volumesOf(part1, part2))
	defer r.Close() //nolint:errcheck
	names, err := traverse(t, r)
	if strings.Join(names, ",") != "a.bin,b.bin" || !errors.Is(err, io.EOF) {
		t.Fatalf("traversal = %v, %v; want [a.bin b.bin] then io.EOF", names, err)
	}
}
