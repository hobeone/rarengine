package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// rar4Member is what reading one entry produced.
type rar4Member struct {
	name     string
	isDir    bool
	link     LinkType
	target   string
	data     []byte
	readErr  error
	closeErr error
}

// readAllRAR4 reads every entry of the archive until NextEntry fails, and
// returns the members and that final error.
func readAllRAR4(t *testing.T, r *Reader) ([]rar4Member, error) {
	t.Helper()
	var out []rar4Member
	for {
		e, err := r.NextEntry()
		if err != nil {
			return out, err
		}
		m := rar4Member{name: e.Header.Name, isDir: e.Header.IsDir, link: e.Header.LinkType, target: e.Header.LinkTarget}
		if m.link == LinkNone {
			m.data, m.readErr = io.ReadAll(e)
		}
		m.closeErr = e.Close()
		out = append(out, m)
		if len(out) > 100 {
			t.Fatal("more than 100 entries; the traversal is not advancing")
		}
	}
}

// storedMember4 is a complete stored member: header and payload.
func storedMember4(name string, flags uint16, content string) []byte {
	n := uint32(len(content))
	return append(rar4File(rar4FileSpec{
		Name: []byte(name), Flags: rar4LongBlock | 0x20 | flags, PackLow: n, UnpLow: n,
		HostOS: 3, CRC: crc32.ChecksumIEEE([]byte(content)), UnpVer: 20, Method: 0x30, Attr: 0x81a4,
	}), content...)
}

func TestRAR4_StoredAtVersion20Decodes(t *testing.T) {
	got, err := readAllRAR4(t, NewReader(fileVolumesOf(t, "testdata/rar4_store.rar")))
	if err != io.EOF {
		t.Fatalf("final NextEntry = %v, want io.EOF", err)
	}
	want := []struct{ name, data string }{{"hello.txt", "hello rardecode"}, {"second.txt", "second file for testing"}}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %+v, want %d", len(got), got, len(want))
	}
	for i, w := range want {
		if got[i].name != w.name || string(got[i].data) != w.data || got[i].readErr != nil || got[i].closeErr != nil {
			t.Errorf("entry %d: %q %q read %v close %v; want %q %q", i, got[i].name, got[i].data,
				got[i].readErr, got[i].closeErr, w.name, w.data)
		}
	}
}

func TestRAR4_MultiVolumeStored(t *testing.T) {
	r := NewReader(fileVolumesOf(t,
		"testdata/rar4_store_multi.rar", "testdata/rar4_store_multi.r00", "testdata/rar4_store_multi.r01"))
	got, err := readAllRAR4(t, r)
	if err != io.EOF || len(got) != 1 {
		t.Fatalf("entries %d, final %v; want one entry and io.EOF", len(got), err)
	}
	m := got[0]
	if m.name != "large.bin" || len(m.data) != 8192 || m.readErr != nil || m.closeErr != nil {
		t.Fatalf("%q: %d bytes, read %v, close %v; want large.bin, 8192 bytes, CRC-clean", m.name, len(m.data), m.readErr, m.closeErr)
	}
	if unrar, err := exec.LookPath("unrar"); err == nil {
		want, err := exec.Command(unrar, "p", "-inul", "testdata/rar4_store_multi.rar", "large.bin").Output()
		if err != nil {
			t.Fatalf("unrar p: %v", err)
		}
		if !bytes.Equal(m.data, want) {
			t.Fatal("large.bin differs from unrar's extraction")
		}
	}
}

// TestRAR4_SolidStored covers solid flags on stored members, which rar itself
// never writes (it drops -s under -m0): the archive and member flags must
// agree, and stored members decode the same either way.
func TestRAR4_SolidStored(t *testing.T) {
	arc := rar4Volume(rar4MainSolid,
		storedMember4("a.txt", 0, "first"),
		storedMember4("b.txt", rar4FileSolid, "second"))
	got, err := readAllRAR4(t, NewReader(volumesOf(arc)))
	if err != io.EOF || len(got) != 2 {
		t.Fatalf("entries %+v, final %v; want two and io.EOF", got, err)
	}
	for i, want := range []string{"first", "second"} {
		if string(got[i].data) != want || got[i].readErr != nil || got[i].closeErr != nil {
			t.Errorf("entry %d: %q read %v close %v; want %q", i, got[i].data, got[i].readErr, got[i].closeErr, want)
		}
	}
}

func TestRAR4_SolidCompressedRefused(t *testing.T) {
	r := NewReader(fileVolumesOf(t, "testdata/rar4_solid_lz.rar"))
	assertRefusedByName(t, r, "text.txt", ErrUnsupportedFormat)
}

func TestRAR4_Directories(t *testing.T) {
	got, err := readAllRAR4(t, NewReader(fileVolumesOf(t, "testdata/rar4_dir.rar")))
	if err != io.EOF {
		t.Fatalf("final NextEntry = %v, want io.EOF", err)
	}
	want := map[string]struct {
		dir  bool
		data string
	}{
		"subdir/top.txt":         {false, "top level"},
		"subdir/nested/deep.txt": {false, "nested content"},
		"subdir/nested":          {true, ""},
		"subdir":                 {true, ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for _, m := range got {
		w, ok := want[m.name]
		if !ok || m.isDir != w.dir || string(m.data) != w.data || m.closeErr != nil {
			t.Errorf("%q: dir %v data %q close %v; want %+v", m.name, m.isDir, m.data, m.closeErr, w)
		}
	}
}

func TestRAR4_ServiceBlocksAreNotMembers(t *testing.T) {
	for _, f := range []string{"testdata/rar4_comment.rar", "testdata/rar4_rr.rar"} {
		got, err := readAllRAR4(t, NewReader(fileVolumesOf(t, f)))
		if err != io.EOF || len(got) != 1 || got[0].name != "hello.txt" || got[0].closeErr != nil {
			t.Errorf("%s: entries %+v, final %v; want only a clean hello.txt", f, got, err)
		}
	}
}

func TestRAR4_RefusedByName(t *testing.T) {
	e := assertRefusedByName(t, NewReader(fileVolumesOf(t, "testdata/rar4_lz.rar")), "text.txt", ErrUnsupportedFormat)
	if msg := e.Close().Error(); !strings.Contains(msg, "method") || !strings.Contains(msg, "unpack version") {
		t.Errorf("refusal %q does not name the method and unpack version", msg)
	}
	// ErrUnsupportedFormat, not ErrUnsupportedEncryptionVersion: that one
	// reports a HEAD_CRYPT the library cannot read and ends the traversal;
	// this is one member, and the archive goes on past it.
	e = assertRefusedByName(t, NewReader(fileVolumesOf(t, "testdata/rar4_encrypted.rar")), "hello.txt",
		ErrUnsupportedFormat)
	if msg := e.Close().Error(); !strings.Contains(msg, "encryption") {
		t.Errorf("refusal %q does not name encryption", msg)
	}
}

func TestRAR4_SymlinksAreLinkEntries(t *testing.T) {
	r := NewReader(fileVolumesOf(t, "testdata/rar4_symlink.rar"))
	targets := map[string]string{"link_rel": "hello.txt", "link_abs": "/etc/passwd", "link_up": "../../x"}
	seen := 0
	for {
		e, err := r.NextEntry()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if want, ok := targets[e.Header.Name]; ok {
			seen++
			if e.Header.LinkType != LinkUnixSymlink || e.Header.LinkTarget != want {
				t.Errorf("%s: LinkType %v LinkTarget %q; want a Unix symlink to %q",
					e.Header.Name, e.Header.LinkType, e.Header.LinkTarget, want)
			}
			if _, err := e.Read(make([]byte, 8)); !errors.Is(err, ErrLinkEntry) {
				t.Errorf("%s: Read = %v, want ErrLinkEntry", e.Header.Name, err)
			}
			if err := e.Close(); err != nil {
				t.Errorf("%s: Close = %v, want nil", e.Header.Name, err)
			}
			continue
		}
		data, err := io.ReadAll(e)
		if e.Header.Name != "hello.txt" || string(data) != "hello rardecode" || err != nil || e.Close() != nil {
			t.Errorf("%q: %q, %v", e.Header.Name, data, err)
		}
	}
	if seen != len(targets) {
		t.Fatalf("saw %d of %d links", seen, len(targets))
	}
}

func TestRAR4_SymlinkWithBadCRCIsRefusedByName(t *testing.T) {
	link := rar4File(rar4FileSpec{
		Name: []byte("lnk"), Flags: rar4LongBlock | 0x20, PackLow: 4, UnpLow: 4,
		HostOS: 3, CRC: crc32.ChecksumIEEE([]byte("targ")) + 1, UnpVer: 20, Method: 0x30, Attr: 0xa1ff,
	})
	arc := rar4Archive(append(link, "targ"...), storedMember4("after.txt", 0, "still here"))
	r := NewReader(volumesOf(arc))
	e := assertRefusedByName(t, r, "lnk", ErrCRCMismatch)
	if e.Header.LinkType != LinkNone || e.Header.LinkTarget != "" {
		t.Errorf("refused link carries LinkType %v LinkTarget %q", e.Header.LinkType, e.Header.LinkTarget)
	}
	got, err := readAllRAR4(t, r)
	if err != io.EOF || len(got) != 1 || string(got[0].data) != "still here" || got[0].closeErr != nil {
		t.Fatalf("after the refused link: %+v, %v; want after.txt clean", got, err)
	}
}

// closeAtOffset serves src until offset at, then closes the Reader from inside
// the Read that reaches it and reports what a closed *os.File reports -- a
// Close landing at a chosen byte, as closeOnScanVolume lands one at a chosen
// call. Single-goroutine, so it needs no synchronisation.
type closeAtOffset struct {
	r   *Reader
	src *bytes.Reader
	at  int
}

func (v *closeAtOffset) Read(p []byte) (int, error) {
	pos := int(v.src.Size()) - v.src.Len()
	if pos >= v.at {
		_ = v.r.Close()
		return 0, os.ErrClosed
	}
	return v.src.Read(p[:min(len(p), v.at-pos)])
}

func (v *closeAtOffset) Close() error { return nil }

// TestRAR4_CloseDuringSymlinkTargetReadIsCancellation pins that a Close
// landing while dispatch reads a RAR4 symlink's target is reported as the
// caller's cancellation, as a Close landing anywhere else in the scan is, and
// not as a member truncated by the archive.
func TestRAR4_CloseDuringSymlinkTargetReadIsCancellation(t *testing.T) {
	link := rar4File(rar4FileSpec{
		Name: []byte("lnk"), Flags: rar4LongBlock | 0x20, PackLow: 4, UnpLow: 4,
		HostOS: 3, CRC: crc32.ChecksumIEEE([]byte("targ")), UnpVer: 20, Method: 0x30, Attr: 0xa1ff,
	})
	arc := rar4Archive(append(link, "targ"...))
	vol := &closeAtOffset{src: bytes.NewReader(arc), at: len(arc) - len(rar4EndHeader()) - len("targ")}
	r := NewReader(oneVolume(vol))
	vol.r = r

	e, err := r.NextEntry()
	if !errors.Is(err, ErrReaderClosed) || errors.Is(err, ErrTruncatedFile) {
		var verdict error
		if e != nil {
			_, verdict = e.Read(nil)
		}
		t.Fatalf("NextEntry = %v (entry verdict %v); want ErrReaderClosed, not a truncated member", err, verdict)
	}
}

func TestRAR4_HeaderEncryptedIsUnsupportedNotCorrupt(t *testing.T) {
	_, err := NewReader(fileVolumesOf(t, "testdata/rar4_hdrenc.rar")).NextEntry()
	if !errors.Is(err, ErrUnsupportedFormat) || errors.Is(err, ErrCorruptArchiveHeader) {
		t.Fatalf("NextEntry = %v, want ErrUnsupportedFormat and not ErrCorruptArchiveHeader", err)
	}
}

// TestRAR4_LargeDeclaredPackSizeIsNotSkippedShort pins that a LARGE member's
// declared payload is skipped by its whole 64-bit count. Read as the low half
// alone, the traversal would land inside the payload and parse what the
// archive put there -- here, a well-formed header for a member that is not in
// the archive.
func TestRAR4_LargeDeclaredPackSizeIsNotSkippedShort(t *testing.T) {
	hidden := storedMember4("hidden.txt", 0, "not a member")
	big := rar4File(rar4FileSpec{
		Name: []byte("big.bin"), Flags: rar4LongBlock | 0x20 | rar4FileLarge,
		PackLow: uint32(len(hidden)), PackHigh: 1, UnpLow: uint32(len(hidden)), UnpHigh: 1,
		HostOS: 3, UnpVer: 20, Method: 0x30, Attr: 0x81a4,
	})
	r := NewReader(volumesOf(rar4Archive(append(big, hidden...))))
	for range 5 {
		e, err := r.NextEntry()
		if err != nil {
			if errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("NextEntry = %v: a set cut inside big.bin's payload ended cleanly", err)
			}
			return
		}
		if e.Header.Name == "hidden.txt" {
			t.Fatal("a header inside big.bin's payload surfaced as a member")
		}
		_, _ = io.ReadAll(e)
		if e.Header.Name == "big.bin" {
			if err := e.Close(); !errors.Is(err, ErrTruncatedFile) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("big.bin Close = %v, want it to end short", err)
			}
		}
	}
	t.Fatal("traversal did not end")
}

func TestRAR4_ContinuationMustMatch(t *testing.T) {
	part := func(name string, flags uint16, content string) []byte {
		return append(rar4File(rar4FileSpec{
			Name: []byte(name), Flags: rar4LongBlock | 0x20 | flags, PackLow: uint32(len(content)), UnpLow: 4,
			HostOS: 3, CRC: crc32.ChecksumIEEE([]byte("abcd")), UnpVer: 20, Method: 0x30, Attr: 0x81a4,
		}), content...)
	}
	v1 := rar4Volume(rar4MainVolume, part("a.bin", rar4FileSplitAfter, "ab"))
	v2 := rar4Volume(rar4MainVolume, part("renamed.bin", rar4FileSplitBefore, "cd"))
	e, err := NewReader(volumesOf(v1, v2)).NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(e)
	if !errors.Is(readErr, ErrCorruptFileHeader) || !errors.Is(e.Close(), ErrCorruptFileHeader) {
		t.Fatalf("Read %v, Close %v; want ErrCorruptFileHeader for a renamed continuation", readErr, e.Close())
	}
}

// TestContinuationChangingUnpackedSizeIsRefused pins that every part of a
// split member must declare the same total, in both formats. rar writes the
// same UnpackedSize in every part of every split member in testdata. A part
// that disagrees is the archive contradicting itself, and the entry, which
// sizes itself from the first part, would otherwise complete without noticing.
func TestContinuationChangingUnpackedSizeIsRefused(t *testing.T) {
	part4 := func(flags uint16, unp uint32, content string) []byte {
		return append(rar4File(rar4FileSpec{
			Name: []byte("a.bin"), Flags: rar4LongBlock | 0x20 | flags, PackLow: uint32(len(content)), UnpLow: unp,
			HostOS: 3, CRC: crc32.ChecksumIEEE([]byte("abcd")), UnpVer: 20, Method: 0x30, Attr: 0x81a4,
		}), content...)
	}
	part5 := func(unp int64, content string, notFirst bool) []byte {
		return rar5Archive(t, false, rar5Member(t, memberSpec{
			name: "a.bin", content: content, unpackedSz: new(unp), packedSz: new(int64(len(content))),
			notFirst: notFirst, notLast: !notFirst, withCRC: notFirst, crcOf: "abcd",
		}))
	}
	for _, tc := range []struct {
		format string
		v1, v2 []byte
	}{
		{"RAR4", rar4Volume(rar4MainVolume, part4(rar4FileSplitAfter, 4, "ab")),
			rar4Volume(rar4MainVolume, part4(rar4FileSplitBefore, 8, "cd"))},
		{"RAR5", part5(4, "ab", false), part5(8, "cd", true)},
	} {
		e, err := NewReader(volumesOf(tc.v1, tc.v2)).NextEntry()
		if err != nil {
			t.Fatalf("%s: NextEntry: %v", tc.format, err)
		}
		_, readErr := io.ReadAll(e)
		if !errors.Is(readErr, ErrCorruptFileHeader) || !strings.Contains(readErr.Error(), "unpacked size") {
			t.Errorf("%s: Read = %v; want ErrCorruptFileHeader from the unpacked-size check", tc.format, readErr)
		}
	}
}

func TestRAR4_TruncatedVolumesAreNotACleanEnd(t *testing.T) {
	arc, err := os.ReadFile("testdata/rar4_store.rar")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("empty volume first", func(t *testing.T) {
		got, err := readAllRAR4(t, NewReader(volumesOf(nil, arc)))
		if len(got) != 2 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%d entries, final %v; want both members, then io.ErrUnexpectedEOF", len(got), err)
		}
	})
	t.Run("cut inside the signature", func(t *testing.T) {
		if _, err := NewReader(volumesOf(rar4Sig[:6])).NextEntry(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("NextEntry = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("cut inside the first file header", func(t *testing.T) {
		start := len(rar4Sig) + int(binary.LittleEndian.Uint16(arc[len(rar4Sig)+5:]))
		size := int(binary.LittleEndian.Uint16(arc[start+5:]))
		for k := start + 1; k < start+size; k++ {
			if _, err := NewReader(volumesOf(arc[:k])).NextEntry(); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("cut %d bytes into the header: NextEntry = %v, want io.ErrUnexpectedEOF", k-start, err)
			}
		}
	})
}

// TestMixedFormatVolumeSetIsRefused pins that one set is one format: a RAR5
// volume after a RAR4 one is not read as more of the archive, and Reset
// forgets the first archive's format.
func TestMixedFormatVolumeSetIsRefused(t *testing.T) {
	rar5 := rar5Archive(t, false, rar5Member(t, memberSpec{name: "five.bin", content: "five", withCRC: true}))
	r := NewReader(volumesOf(rar4Archive(storedMember4("four.txt", 0, "four")), rar5))
	got, err := readAllRAR4(t, r)
	if len(got) != 1 || got[0].name != "four.txt" || !errors.Is(err, ErrCorruptArchiveHeader) {
		t.Fatalf("entries %+v, final %v; want four.txt, then ErrCorruptArchiveHeader", got, err)
	}

	r.Reset(volumesOf(rar5))
	got, err = readAllRAR4(t, r)
	if err != io.EOF || len(got) != 1 || string(got[0].data) != "five" || got[0].closeErr != nil {
		t.Fatalf("after Reset onto a RAR5 archive: %+v, %v; want five.bin clean", got, err)
	}
}

func TestRAR4_InspectEntryPointsStillRefuse(t *testing.T) {
	arc, err := os.ReadFile("testdata/rar4_store.rar")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPassword(bytes.NewReader(arc), "x"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("VerifyPassword = %v, want ErrUnsupportedFormat", err)
	}
	if _, _, err := VolumeNumber(bytes.NewReader(arc)); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("VolumeNumber = %v, want ErrUnsupportedFormat", err)
	}
}

// TestRAR4_OracleAgreement holds every decodable fixture to unrar: the same
// member names, and each regular member's bytes equal to `unrar p`.
func TestRAR4_OracleAgreement(t *testing.T) {
	unrar, err := exec.LookPath("unrar")
	if err != nil {
		t.Skip("unrar binary not found on path")
	}
	for _, f := range []string{"rar4_store.rar", "rar4_dir.rar", "rar4_unicode.rar", "rar4_comment.rar",
		"rar4_rr.rar", "rar4_symlink.rar"} {
		path := "testdata/" + f
		list, err := exec.Command(unrar, "lb", path).Output()
		if err != nil {
			t.Fatalf("%s: unrar lb: %v", f, err)
		}
		want := strings.Fields(string(list))
		got, err := readAllRAR4(t, NewReader(fileVolumesOf(t, path)))
		if err != io.EOF {
			t.Fatalf("%s: final NextEntry = %v", f, err)
		}
		var names []string
		for _, m := range got {
			names = append(names, m.name)
			if m.isDir || m.link != LinkNone {
				continue
			}
			out, err := exec.Command(unrar, "p", "-inul", path, m.name).Output()
			if err != nil {
				t.Fatalf("%s: unrar p %s: %v", f, m.name, err)
			}
			if !bytes.Equal(m.data, out) || m.closeErr != nil {
				t.Errorf("%s: %s differs from unrar's (close %v)", f, m.name, m.closeErr)
			}
		}
		if strings.Join(names, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s: names %q, unrar lists %q", f, names, want)
		}
	}
}

// TestRAR4_StoredAfterRefusedSolidMemberDecodes pins that refusing a RAR4
// member does not condemn the stored members after it in a solid run. No RAR4
// member ever writes the window -- only stored ones are decoded, and they
// bypass it -- so there is no history for a successor to have lost, and
// refusing pic.jpg as ErrSolidStreamBroken would accuse it of depending on
// bytes nothing wrote. rar -s -msjpg writes exactly this: a compressed member,
// then a stored member flagged solid.
func TestRAR4_StoredAfterRefusedSolidMemberDecodes(t *testing.T) {
	const fixture = "testdata/rar4_solid_mixed.rar"
	r := NewReader(fileVolumesOf(t, fixture))
	assertRefusedByName(t, r, "text.txt", ErrUnsupportedFormat)
	got, err := readAllRAR4(t, r)
	if err != io.EOF || len(got) != 1 || got[0].name != "pic.jpg" {
		t.Fatalf("after the refused member: %+v, %v; want pic.jpg and io.EOF", got, err)
	}
	if got[0].readErr != nil || got[0].closeErr != nil || len(got[0].data) != 2048 {
		t.Fatalf("pic.jpg: %d bytes, read %v, close %v; want 2048 bytes, clean",
			len(got[0].data), got[0].readErr, got[0].closeErr)
	}
	if unrar, err := exec.LookPath("unrar"); err == nil {
		want, err := exec.Command(unrar, "p", "-inul", fixture, "pic.jpg").Output()
		if err != nil {
			t.Fatalf("unrar p: %v", err)
		}
		if !bytes.Equal(got[0].data, want) {
			t.Fatal("pic.jpg differs from unrar's extraction")
		}
	}
}
