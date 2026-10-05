package rarengine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

// Issue #77: a RAR5 symlink or hard link is a file header carrying a
// redirection extra record and NO payload. Its declared UnpackedSize is not a
// content size -- a symlink declares the length of its target string, a hard
// link the size of the file it points at -- so before the record was parsed a
// link was admitted as an ordinary file and failed with ErrTruncatedFile, and a
// hard link to anything over 1 MiB never got that far: PackedSize 0 expands
// without limit, so the rar-bomb guard refused it first.
//
// The real archives come from testdata/generate.sh (section 23). Everything
// the real rar cannot be made to write -- an unknown kind, a record with no
// target, a link that also carries bytes -- is built with testbuild_test.go.

// redirectionBody is a well-formed redirection record body (everything after
// the record-type vint): kind, flags, target length, target.
func redirectionBody(kind uint64, target string) []byte {
	var b bytes.Buffer
	b.Write(encodeVint(kind))
	b.Write(encodeVint(0)) // flags: bit 0 would say the target is a directory
	b.Write(encodeVint(uint64(len(target))))
	b.WriteString(target)
	return b.Bytes()
}

func redirection(body []byte) extraRecordSpec {
	return extraRecordSpec{Type: extraRecordRedirection, Body: body}
}

// linkMember builds a link block as rar writes one: declared size, no payload.
func linkMember(name string, declared int64, recs ...extraRecordSpec) []byte {
	return buildRAR5Member(memberSpec{
		name:         name,
		unpackedSz:   new(declared),
		packedSz:     new(int64(0)),
		hostOS:       1,
		rawCRC:       new(uint32(0)),
		extraRecords: recs,
	})
}

func fixtureReader(t *testing.T, name string) *Reader {
	t.Helper()
	return NewReader(fileVolumesOf(t, "testdata/"+name))
}

// assertLinkEntry checks everything a clean link member promises: it reads as
// empty with io.EOF, repeatably, and closes with nil -- with no
// ErrTruncatedFile and no checksum comparison, though the header declares a
// size and a zero CRC32.
func assertLinkEntry(t *testing.T, e *Entry) {
	t.Helper()
	buf := make([]byte, 64)
	for i := range 2 {
		if n, err := e.Read(buf); n != 0 || err != io.EOF {
			t.Fatalf("Read #%d of link %q = %d, %v; want 0, io.EOF", i, e.Header.Name, n, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close of link %q = %v, want nil", e.Header.Name, err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("second Close of link %q = %v, want nil", e.Header.Name, err)
	}
}

func nextOrFatal(t *testing.T, r *Reader) *Entry {
	t.Helper()
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	return e
}

func expectContent(t *testing.T, e *Entry, name, want string) {
	t.Helper()
	if e.Header.Name != name {
		t.Fatalf("entry = %q, want %q", e.Header.Name, name)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close %s: %v", name, err)
	}
}

func expectEOF(t *testing.T, r *Reader) {
	t.Helper()
	if e, err := r.NextEntry(); !errors.Is(err, io.EOF) {
		t.Fatalf("NextEntry after the last member = %v, %v; want io.EOF", e, err)
	}
}

// Real rar archives: both link kinds rar can write, each after the file it
// points at, and a hard link over the 1 MiB bomb floor.
func TestLinkMembersFromRealArchives(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		r := fixtureReader(t, "rar5_link_symlink.rar")
		expectContent(t, nextOrFatal(t, r), "real.txt", "real text")
		e := nextOrFatal(t, r)
		fh := e.Header
		if fh.Name != "link.txt" || fh.LinkType != LinkUnixSymlink || fh.LinkTarget != "real.txt" {
			t.Fatalf("header = %q %v %q, want link.txt, LinkUnixSymlink, real.txt",
				fh.Name, fh.LinkType, fh.LinkTarget)
		}
		// The header stays faithful: 8 is the target string's length.
		if fh.UnpackedSize != 8 || fh.PackedSize != 0 {
			t.Fatalf("sizes = %d/%d, want the declared 8/0", fh.UnpackedSize, fh.PackedSize)
		}
		assertLinkEntry(t, e)
		expectEOF(t, r)
	})

	t.Run("hard link", func(t *testing.T) {
		r := fixtureReader(t, "rar5_link_hard.rar")
		expectContent(t, nextOrFatal(t, r), "orig.txt", "orig content")
		e := nextOrFatal(t, r)
		fh := e.Header
		if fh.Name != "hard.txt" || fh.LinkType != LinkHardLink || fh.LinkTarget != "orig.txt" {
			t.Fatalf("header = %q %v %q, want hard.txt, LinkHardLink, orig.txt",
				fh.Name, fh.LinkType, fh.LinkTarget)
		}
		// 12 is the size of the file it points at, not content it carries.
		if fh.UnpackedSize != 12 || fh.PackedSize != 0 {
			t.Fatalf("sizes = %d/%d, want the declared 12/0", fh.UnpackedSize, fh.PackedSize)
		}
		assertLinkEntry(t, e)
		expectEOF(t, r)
	})

	// 1100000 declared, nothing packed: over the 1 MiB floor with a ratio of
	// infinity. Refused as ErrRarBombDetected until the link was admitted
	// ahead of the guard.
	t.Run("hard link over the bomb floor", func(t *testing.T) {
		r := fixtureReader(t, "rar5_link_hard_large.rar")
		e := nextOrFatal(t, r)
		if e.Header.Name != "zhard.bin" || e.Header.LinkType != LinkHardLink ||
			e.Header.LinkTarget != "z.bin" || e.Header.UnpackedSize != 1100000 {
			t.Fatalf("header = %+v", e.Header)
		}
		assertLinkEntry(t, e)
		expectEOF(t, r)
	})
}

// The members on both sides of a link in a SOLID archive decode byte-exact.
//
// -ds keeps rar from sorting its input, so the link really is second of three.
// c.txt is nearly all back-reference into a.txt, so it only decodes if the
// link left the window history alone.
func TestSolidMembersAroundALinkDecode(t *testing.T) {
	r := fixtureReader(t, "rar5_link_solid.rar")
	expectContent(t, nextOrFatal(t, r), "a.txt",
		"AAAA first member text, compressible compressible compressible")
	e := nextOrFatal(t, r)
	if e.Header.Name != "mid.lnk" || e.Header.LinkType != LinkUnixSymlink || e.Header.LinkTarget != "a.txt" {
		t.Fatalf("middle member = %q %v %q", e.Header.Name, e.Header.LinkType, e.Header.LinkTarget)
	}
	if !e.Header.Solid {
		t.Fatal("fixture's link no longer carries the solid flag; regenerate it as generate.sh describes")
	}
	assertLinkEntry(t, e)
	expectContent(t, nextOrFatal(t, r), "c.txt",
		"BBBB third member text, compressible compressible compressible a.txt")
	expectEOF(t, r)
}

// splitBlocks cuts a volume into its signature and blocks, each block with the
// payload it declares.
func splitBlocks(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var blocks [][]byte
	rest := data[len(rar5Signature):]
	for len(rest) > 0 {
		h, err := readBlockHeader(bytes.NewReader(rest))
		if err != nil {
			t.Fatalf("splitBlocks: %v", err)
		}
		size, n, err := decodeVint(rest[4:])
		if err != nil {
			t.Fatalf("splitBlocks: %v", err)
		}
		total := 4 + n + int(size) + int(h.DataSize)
		blocks = append(blocks, rest[:total])
		rest = rest[total:]
	}
	return blocks
}

// A link must not touch the window, whatever its own Solid flag says.
//
// Rewrites the real solid archive so its link header says NON-solid, which is
// the header a link is free to carry: BeginFile(false) on it would reset the
// history c.txt back-references into, and c.txt -- every byte of it a copy out
// of a.txt -- would fail instead of decoding.
func TestNonSolidFlaggedLinkInsideSolidArchiveLeavesHistoryAlone(t *testing.T) {
	data, err := os.ReadFile("testdata/rar5_link_solid.rar")
	if err != nil {
		t.Fatal(err)
	}
	blocks := splitBlocks(t, data)
	link := -1
	for i, b := range blocks {
		if bytes.Contains(b, []byte("mid.lnk")) {
			link = i
		}
	}
	if link < 0 {
		t.Fatal("no link block found in the fixture")
	}
	_, n, _ := decodeVint(blocks[link][4:])
	payload := append([]byte(nil), blocks[link][4+n:]...)
	// type, block flags, extra size, data size, file flags, unpacked size,
	// attributes (3-byte vint), CRC32 (4 bytes), then the compression info,
	// which rar writes as the two-byte vint c0 00 (the solid bit, padded).
	const compInfo = 4 + 1 + 1 + 3 + 4
	if payload[compInfo] != 0xc0 || payload[compInfo+1] != 0 {
		t.Fatalf("compression info = % x at %d, want c0 00 (solid, nothing else); the fixture's layout moved",
			payload[compInfo:compInfo+2], compInfo)
	}
	payload[compInfo] = 0x80 // the same two-byte vint with the solid bit cleared
	blocks[link] = rar5Block(payload)

	out := append([]byte(nil), rar5Signature...)
	for _, b := range blocks {
		out = append(out, b...)
	}

	r := NewReader(volumesOf(out))
	expectContent(t, nextOrFatal(t, r), "a.txt",
		"AAAA first member text, compressible compressible compressible")
	e := nextOrFatal(t, r)
	if e.Header.Solid || e.Header.LinkType != LinkUnixSymlink {
		t.Fatalf("rewritten link header = solid %v, kind %v", e.Header.Solid, e.Header.LinkType)
	}
	assertLinkEntry(t, e)
	expectContent(t, nextOrFatal(t, r), "c.txt",
		"BBBB third member text, compressible compressible compressible a.txt")
}

// A link does not repair a damaged window either. BeginFile(false) clears the
// damage flag, so a link that called it would let the solid member after a
// refused one decode against history nobody wrote.
func TestLinkDoesNotClearWindowDamage(t *testing.T) {
	bomb := rar5Member(t, memberSpec{
		name: "bomb.bin", unpackedSz: new(int64(2 << 20)), packedSz: new(int64(0)),
		solid: true,
	})
	stream := rar5Archive(t, true,
		bomb,
		linkMember("link", 3, redirection(redirectionBody(1, "x"))),
		rar5Member(t, memberSpec{name: "after.txt", content: "after", solid: true, withCRC: true}),
	)
	r := NewReader(volumesOf(stream))

	assertRefusedByName(t, r, "bomb.bin", ErrRarBombDetected)
	assertLinkEntry(t, nextOrFatal(t, r))
	assertRefusedByName(t, r, "after.txt", ErrSolidStreamBroken)
}

// And it does not CAUSE damage: a solid member after a link is not refused for
// a window that was never disturbed.
func TestLinkDoesNotMarkTheWindowDamaged(t *testing.T) {
	stream := rar5Archive(t, true,
		rar5Member(t, memberSpec{name: "first.txt", content: "first", solid: true, withCRC: true}),
		linkMember("link", 3, redirection(redirectionBody(1, "x"))),
		rar5Member(t, memberSpec{name: "after.txt", content: "after", solid: true, withCRC: true}),
	)
	r := NewReader(volumesOf(stream))
	expectContent(t, nextOrFatal(t, r), "first.txt", "first")
	assertLinkEntry(t, nextOrFatal(t, r))
	expectContent(t, nextOrFatal(t, r), "after.txt", "after")
	expectEOF(t, r)
}

// The bomb guard is untouched: it still refuses a member WITHOUT a redirection
// record that declares the same sizes. Only which members reach it changed.
func TestBombGuardStillRefusesAnOrdinaryMemberWithALinksSizes(t *testing.T) {
	declared := int64(2 << 20)
	t.Run("link is admitted", func(t *testing.T) {
		stream := rar5Archive(t, false,
			linkMember("big.lnk", declared, redirection(redirectionBody(uint64(LinkHardLink), "big.bin"))))
		e := nextOrFatal(t, NewReader(volumesOf(stream)))
		if e.Header.UnpackedSize != declared {
			t.Fatalf("UnpackedSize = %d, want the declared %d", e.Header.UnpackedSize, declared)
		}
		assertLinkEntry(t, e)
	})
	t.Run("the same sizes without the record are a bomb", func(t *testing.T) {
		stream := rar5Archive(t, false, linkMember("big.bin", declared))
		assertRefusedByName(t, NewReader(volumesOf(stream)), "big.bin", ErrRarBombDetected)
	})
}

// Every kind the format defines is admitted, and the target comes out exactly
// as stored: not path-cleaned, not stripped of its "..", not made relative.
func TestLinkKindsAndRawTargets(t *testing.T) {
	cases := []struct {
		name   string
		kind   uint64
		want   LinkType
		target string
	}{
		{"unix symlink", 1, LinkUnixSymlink, "../lib/x"},
		{"windows symlink", 2, LinkWindowsSymlink, `..\lib\x`},
		{"windows junction", 3, LinkWindowsJunction, `C:\Windows`},
		{"hard link", 4, LinkHardLink, "dir/orig.txt"},
		{"file copy", 5, LinkFileCopy, "/etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := rar5Archive(t, false,
				linkMember("l", 9, redirection(redirectionBody(tc.kind, tc.target))))
			e := nextOrFatal(t, NewReader(volumesOf(stream)))
			if e.Header.LinkType != tc.want || e.Header.LinkTarget != tc.target {
				t.Fatalf("link = %v %q, want %v %q",
					e.Header.LinkType, e.Header.LinkTarget, tc.want, tc.target)
			}
			assertLinkEntry(t, e)
		})
	}
}

// Each malformed link is refused BY NAME with the error that says why, and the
// traversal goes on to the member after it.
func TestMalformedLinksAreRefusedByName(t *testing.T) {
	var farTooLong bytes.Buffer // a target length with the sign bit of an int64 set
	farTooLong.Write(encodeVint(1))
	farTooLong.Write(encodeVint(0))
	farTooLong.Write(encodeVint(1 << 63))
	farTooLong.WriteString("target")

	var maxLen bytes.Buffer
	maxLen.Write(encodeVint(1))
	maxLen.Write(encodeVint(0))
	maxLen.Write(encodeVint(^uint64(0)))
	maxLen.WriteString("target")

	var overrun bytes.Buffer // five bytes declared, three present
	overrun.Write(encodeVint(1))
	overrun.Write(encodeVint(0))
	overrun.Write(encodeVint(5))
	overrun.WriteString("abc")

	cases := []struct {
		name string
		spec memberSpec
		want error
		// kindStays says the header still reports the link kind: the record
		// was fine and the HEADER contradicted itself. A refused record never
		// reports a kind.
		kindStays bool
	}{
		{name: "empty target", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(redirectionBody(1, ""))}}},
		{name: "NUL in the target", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(redirectionBody(1, "a\x00b"))}}},
		{name: "target length overruns the record", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(overrun.Bytes())}}},
		{name: "target length with the int64 sign bit set", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(farTooLong.Bytes())}}},
		{name: "target length of 2^64-1", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(maxLen.Bytes())}}},
		{name: "record ends after the kind", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(encodeVint(1))}}},
		{name: "empty record", want: ErrCorruptFileHeader,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(nil)}}},
		{name: "kind 0", want: ErrUnsupportedFormat,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(redirectionBody(0, "t"))}}},
		{name: "kind 6", want: ErrUnsupportedFormat,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(redirectionBody(6, "t"))}}},
		{name: "kind 99", want: ErrUnsupportedFormat,
			spec: memberSpec{extraRecords: []extraRecordSpec{redirection(redirectionBody(99, "t"))}}},
		{name: "a link that also carries bytes", want: ErrCorruptFileHeader, kindStays: true,
			spec: memberSpec{content: "xxxxx", extraRecords: []extraRecordSpec{redirection(redirectionBody(1, "t"))}}},
		{name: "a link that continues into a further part", want: ErrCorruptFileHeader, kindStays: true,
			spec: memberSpec{notLast: true, extraRecords: []extraRecordSpec{redirection(redirectionBody(1, "t"))}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			spec.name = "bad.lnk"
			spec.hostOS = 1
			spec.unpackedSz = new(int64(5))
			stream := rar5Archive(t, false,
				rar5Member(t, spec),
				rar5Member(t, memberSpec{name: "after.txt", content: "after", withCRC: true}),
			)
			r := NewReader(volumesOf(stream))
			e := assertRefusedByName(t, r, "bad.lnk", tc.want)
			// The two refusal sentinels are distinct: a kind this library
			// does not know is not a corrupt header, and the reverse.
			other := ErrUnsupportedFormat
			if tc.want == ErrUnsupportedFormat {
				other = ErrCorruptFileHeader
			}
			if errors.Is(e.Close(), other) {
				t.Fatalf("verdict also matches %v", other)
			}
			if tc.kindStays && e.Header.LinkType != LinkUnixSymlink {
				t.Fatalf("LinkType = %v, want the kind the record stated", e.Header.LinkType)
			}
			if !tc.kindStays && (e.Header.LinkType != LinkNone || e.Header.LinkTarget != "") {
				t.Fatalf("a refused record reported %v %q", e.Header.LinkType, e.Header.LinkTarget)
			}
			expectContent(t, nextOrFatal(t, r), "after.txt", "after")
		})
	}
}

// The two header contradictions are refused by the PARSER, not left to be
// caught later. A link declaring a further part would otherwise be admitted
// and fail only at Read, where Entry.verifyChecksum happens to refuse the same
// combination with the same sentinel -- so the traversal-level test above
// cannot tell a parse refusal from that accident.
func TestLinkHeaderContradictionsAreRefusedAtParse(t *testing.T) {
	rec := redirection(redirectionBody(1, "t"))
	for _, tc := range []struct {
		name string
		spec memberSpec
	}{
		{"declares payload", memberSpec{content: "xxxxx", unpackedSz: new(int64(5)), extraRecords: []extraRecordSpec{rec}}},
		{"declares a further part", memberSpec{notLast: true, unpackedSz: new(int64(5)), extraRecords: []extraRecordSpec{rec}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			spec.name = "l"
			fh, err := parseBuiltHeader(t, buildRAR5Member(spec))
			if !errors.Is(err, ErrCorruptFileHeader) {
				t.Fatalf("err = %v, want ErrCorruptFileHeader", err)
			}
			if fh == nil || fh.Name != "l" {
				t.Fatalf("header = %+v, want one to refuse the member by name", fh)
			}
		})
	}
}

// A second redirection record joins the once-per-type rule. Two of them would
// otherwise let the later one rewrite where a link points, with a nil error.
func TestDuplicateRedirectionRecordIsRefused(t *testing.T) {
	stream := rar5Archive(t, false,
		linkMember("dup.lnk", 1,
			redirection(redirectionBody(1, "first")),
			redirection(redirectionBody(4, "second"))),
	)
	assertRefusedByName(t, NewReader(volumesOf(stream)), "dup.lnk", ErrCorruptFileHeader)
}

// The FIRST record of a type is authoritative, whether or not it parses, and
// every record is still examined after a failure.
func TestFirstRedirectionRecordIsAuthoritative(t *testing.T) {
	t.Run("a valid first record is never overwritten", func(t *testing.T) {
		fh, err := parseBuiltHeader(t, linkMember("l", 1,
			redirection(redirectionBody(1, "first")),
			redirection(redirectionBody(4, "second"))))
		if !errors.Is(err, ErrCorruptFileHeader) {
			t.Fatalf("err = %v, want ErrCorruptFileHeader", err)
		}
		if fh == nil || fh.LinkType != LinkUnixSymlink || fh.LinkTarget != "first" {
			t.Fatalf("header = %+v, want the first record's symlink to \"first\"", fh)
		}
	})

	t.Run("a malformed first record is not repaired by a later one", func(t *testing.T) {
		fh, err := parseBuiltHeader(t, linkMember("l", 1,
			redirection(redirectionBody(1, "")),
			redirection(redirectionBody(1, "second"))))
		if !errors.Is(err, ErrCorruptFileHeader) {
			t.Fatalf("err = %v, want the first record's ErrCorruptFileHeader", err)
		}
		if fh == nil || fh.LinkType != LinkNone || fh.LinkTarget != "" {
			t.Fatalf("header = %+v, want no link: the second record must not be read", fh)
		}
	})

	t.Run("the first error stands over a later duplicate's", func(t *testing.T) {
		_, err := parseBuiltHeader(t, linkMember("l", 1,
			redirection(redirectionBody(99, "t")),
			redirection(redirectionBody(1, "second"))))
		if !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("err = %v, want the first record's ErrUnsupportedFormat", err)
		}
	})

	t.Run("a malformed record ahead of the encryption record does not hide it", func(t *testing.T) {
		fh, err := parseBuiltHeader(t, linkMember("l", 1,
			redirection(redirectionBody(1, "")),
			extraRecordSpec{Type: extraRecordEncryption, Body: encryptionRecordBody(0, 0xAA)}))
		if err == nil || fh == nil || !fh.Encrypted {
			t.Fatalf("fh = %+v, err = %v; want a refused header that still reports Encrypted", fh, err)
		}
	})
}

// The version record (type 4) sits between the records this library parses and
// the redirection record. It stays unparsed and untracked: repeating it is not
// a duplicate, and it does not disturb the link beside it.
func TestVersionRecordIsNotTracked(t *testing.T) {
	versionRec := extraRecordSpec{Type: extraRecordVersion, Body: encodeVint(0)}
	fh, err := parseBuiltHeader(t, linkMember("l", 1,
		versionRec, redirection(redirectionBody(1, "t")), versionRec))
	if err != nil {
		t.Fatalf("a repeated version record was refused: %v", err)
	}
	if fh.LinkType != LinkUnixSymlink || fh.LinkTarget != "t" {
		t.Fatalf("link = %v %q", fh.LinkType, fh.LinkTarget)
	}
}

// An ordinary member is not a link, whatever else it carries.
func TestOrdinaryMemberReportsNoLink(t *testing.T) {
	fh := parseBuiltMember(t, rar5Member(t, memberSpec{name: "plain.txt", content: "hello", withCRC: true}))
	if fh.LinkType != LinkNone || fh.LinkTarget != "" {
		t.Fatalf("link = %v %q, want none", fh.LinkType, fh.LinkTarget)
	}
}
