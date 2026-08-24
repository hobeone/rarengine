package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TestUnsupportedUnpackVersionIsRefused pins that a member declaring a
// compression algorithm this library does not implement is refused rather than
// handed to the RAR5 decoder.
//
// RAR 7.0 raised this field and changed nothing else a traversal can see: the
// signature, block framing and vint encoding are identical, which is why the
// signature check cannot separate the two formats. Every member with a nonzero
// method went to the RAR5 decoder regardless, produced garbage, and was caught
// -- if at all -- by the CRC32 after the whole member had been decompressed
// and delivered to the caller.
//
// Mutation check: remove the UnpackVersion test from dispatch and this member
// decodes as RAR5, reporting ErrCRCMismatch on content that was never RAR5 to
// begin with.
func TestUnsupportedUnpackVersionIsRefused(t *testing.T) {
	// The field is six bits, so every one of them has to reach the check.
	// 32 is the case a too-narrow mask gets wrong: under 0x1f it reads as 0
	// and the member is accepted as RAR 5.0, which is the same silent
	// mis-decode this guard exists to stop. 63 is all six bits set.
	for _, version := range []uint64{1, 2, 5, 32, 63} {
		t.Run(fmt.Sprintf("version%d", version), func(t *testing.T) {
			member := rar5Member(t, memberSpec{
				name: "rar7.bin", content: "would be decoded as RAR5",
				withCRC: true, unpackVersion: version,
			})

			r := readerFor(rar5Archive(t, false, member))
			e, err := r.NextEntry()
			if err != nil {
				t.Fatalf("NextEntry: %v", err)
			}

			// The refusal is the member's verdict, not the archive's:
			// NextEntry's error set stays archive-level, and the header still
			// names the member.
			if e.Header.Name != "rar7.bin" {
				t.Fatalf("entry name = %q, want rar7.bin", e.Header.Name)
			}
			if got := e.Header.UnpackVersion; got != int(version) {
				t.Fatalf("UnpackVersion = %d, want %d -- the mask dropped a "+
					"bit of the declared version", got, version)
			}

			got, readErr := io.ReadAll(e)
			if len(got) != 0 {
				t.Fatalf("refused member produced %d bytes: %q", len(got), got)
			}
			for _, c := range []struct {
				what string
				err  error
			}{{"Read", readErr}, {"Close", e.Close()}} {
				if !errors.Is(c.err, ErrUnsupportedFormat) {
					t.Fatalf("%s = %v, want ErrUnsupportedFormat", c.what, c.err)
				}
				// The version is what makes the error actionable:
				// "unsupported archive format" alone does not tell a caller
				// their archive is RAR7.
				want := fmt.Sprintf("unpack version %d", version)
				if !strings.Contains(c.err.Error(), want) {
					t.Fatalf("%s = %q, want it to name %q", c.what, c.err, want)
				}
			}
		})
	}
}

// Refusing one member must not end the archive. The version field is
// per-member, and a traversal that stopped on it would hide every readable
// member behind the first unreadable one.
func TestUnsupportedUnpackVersionDoesNotEndTraversal(t *testing.T) {
	const good = "an ordinary RAR5 member"
	r := readerFor(rar5Archive(t, false,
		rar5Member(t, memberSpec{
			name: "rar7.bin", content: "unsupported", withCRC: true, unpackVersion: 1,
		}),
		rar5Member(t, memberSpec{name: "ok.bin", content: good, withCRC: true}),
	))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("first verdict = %v, want ErrUnsupportedFormat", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry after a refused member: %v", err)
	}
	if second.Header.Name != "ok.bin" {
		t.Fatalf("second entry = %q, want ok.bin -- the refused member's "+
			"payload was not discarded", second.Header.Name)
	}
	got, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("reading the member behind a refused one: %v", err)
	}
	if string(got) != good {
		t.Fatalf("content = %q, want %q", got, good)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
}

// Version 0 is RAR 5.0 and must stay unaffected -- that is every archive this
// library exists to read, and a version check that refused them would be worse
// than no check at all.
func TestRAR5UnpackVersionIsAccepted(t *testing.T) {
	const content = "ordinary content"
	r := readerFor(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "ok.bin", content: content, withCRC: true})))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.UnpackVersion != 0 {
		t.Fatalf("UnpackVersion = %d, want 0", e.Header.UnpackVersion)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
}

// Every real fixture in testdata declares version 0. This is the guard against
// a mask that is wrong in a way the hand-built members cannot show: they set
// the field directly, so a bad mask would agree with them.
func TestFixturesDeclareRAR5UnpackVersion(t *testing.T) {
	for _, name := range []string{
		"rar5_store.rar", "rar5_compress.rar", "rar5_solid.rar",
		"rar5_blake2.rar", "rar5_exe_filter.rar", "rar5_directory.rar",
	} {
		t.Run(name, func(t *testing.T) {
			r := readerFor(fixtureBytes(t, name))
			for {
				e, err := r.NextEntry()
				if errors.Is(err, io.EOF) {
					return
				}
				if err != nil {
					t.Fatalf("NextEntry: %v", err)
				}
				if e.Header.UnpackVersion != unpackVersionRAR5 {
					t.Fatalf("%s: UnpackVersion = %d, want %d",
						e.Header.Name, e.Header.UnpackVersion, unpackVersionRAR5)
				}
				_ = e.Close()
			}
		})
	}
}

// TestRealRAR7ArchiveIsRefused is the fixture-backed half: an archive produced
// by rar 7.11 itself, not a hand-built header with a version field set.
//
// It matters that this is real. Every other test here builds the member with
// rar5Member, which writes whatever version it is told and therefore cannot
// show that RAR actually uses this field, that the signature is genuinely
// identical, or that the value is where the spec says it is.
//
// What this fixture does NOT show: removing the guard makes it decode to the
// correct 15 bytes, not to garbage. The member is too small to reach anything
// RAR7 codes differently, so the RAR5 decoder happens to be right about it.
// That is a limitation of a 106-byte fixture, not evidence the guard is
// unnecessary -- a version field cannot be checked lazily on the chance that a
// particular member survives being decoded by the wrong algorithm, and the
// archives where it would not survive are the multi-gigabyte ones this
// fixture exists to avoid committing.
//
// testdata/rar5_dict4g.rar is the same archive one step below the boundary and
// must still decode. Together they pin both sides: RAR5 records the dictionary
// as a 4-bit exponent, so 128KB<<15 = 4 GB is the largest it can express;
// asking for 5 GB is what raises the version. Refusing version 1 while
// accepting the 4 GB archive is exactly the line this guard has to draw, and
// a guard keyed on the dictionary rather than the version would fail it --
// rar5_dict4g.rar declares 128 times this library's window and decodes fine.
func TestRealRAR7ArchiveIsRefused(t *testing.T) {
	t.Run("rar7 is refused", func(t *testing.T) {
		r := readerFor(fixtureBytes(t, "rar7_unpack_version.rar"))
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}
		if e.Header.UnpackVersion == unpackVersionRAR5 {
			t.Fatal("fixture declares version 0; it no longer exercises this path")
		}
		got, readErr := io.ReadAll(e)
		if len(got) != 0 {
			t.Fatalf("refused member produced %d bytes: %q", len(got), got)
		}
		if !errors.Is(readErr, ErrUnsupportedFormat) {
			t.Fatalf("Read = %v, want ErrUnsupportedFormat", readErr)
		}
		if err := e.Close(); !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("Close = %v, want ErrUnsupportedFormat", err)
		}
	})

	// The signature is what makes the version check necessary rather than
	// merely tidy: it is byte-identical to every RAR5 archive, so nothing
	// before the file header can tell the two formats apart.
	t.Run("signature is indistinguishable from RAR5", func(t *testing.T) {
		rar7 := fixtureBytes(t, "rar7_unpack_version.rar")
		rar5 := fixtureBytes(t, "rar5_store.rar")
		if !bytes.Equal(rar7[:8], rar5[:8]) {
			t.Fatalf("signatures differ: rar7=%x rar5=%x -- if these ever "+
				"diverge, the format could be rejected at the signature",
				rar7[:8], rar5[:8])
		}
	})

	// One step below the boundary: the largest dictionary RAR5 can express.
	// It must decode, and it must not be refused for declaring a dictionary
	// far larger than this library's 32 MB window.
	t.Run("rar5 at the 4GB dictionary ceiling still decodes", func(t *testing.T) {
		r := readerFor(fixtureBytes(t, "rar5_dict4g.rar"))
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}
		if e.Header.UnpackVersion != unpackVersionRAR5 {
			t.Fatalf("UnpackVersion = %d, want %d", e.Header.UnpackVersion, unpackVersionRAR5)
		}
		got, err := io.ReadAll(e)
		if err != nil {
			t.Fatalf("ReadAll = %v; a 4 GB declared dictionary is not a "+
				"reason to refuse a RAR5 member", err)
		}
		if string(got) != "hello rardecode" {
			t.Fatalf("content = %q", got)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
	})
}

// TestContinuationChangingUnpackVersionIsRefused pins the version check on the
// volume-advance path, not only at admission.
//
// dispatch refuses a nonzero version, but it only ever sees FIRST blocks --
// continuation headers are skipped there by the !FirstBlock test. So a member
// could be admitted declaring version 0 and continue, on the next volume,
// declaring version 1, and that continuation's payload went to the RAR5
// decoder as though the member had never changed formats.
//
// Compared against e.Header.UnpackVersion rather than tested for zero: the
// first block is already known to be version 0, so one comparison covers both
// "changed" and "unsupported", and it says what the rule actually is -- a
// continuation must prove it belongs to the member it is spliced into, which
// is the same reason Name, Method and Encrypted are checked here.
//
// Mutation check: drop UnpackVersion from that comparison and this reads the
// continuation's bytes with a nil error.
func TestContinuationChangingUnpackVersionIsRefused(t *testing.T) {
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa", unpackedSz: 8, packedSz: 4, notLast: true,
	}))
	v2 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "bbbb", notFirst: true, unpackVersion: 1,
	}))

	r := NewReader(volumesOf(v1, v2))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.UnpackVersion != unpackVersionRAR5 {
		t.Fatalf("first block UnpackVersion = %d, want 0 -- this test needs a "+
			"member admitted as RAR5", e.Header.UnpackVersion)
	}

	got, err := io.ReadAll(e)
	if !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("reading split.bin = %q, %v; want ErrCorruptFileHeader for a "+
			"continuation declaring a different unpack version", got, err)
	}
	if bytes.Contains(got, []byte("bbbb")) {
		t.Fatalf("split.bin was served %q from a continuation declaring a "+
			"format this library does not decode", got)
	}
}
