package rarengine

import (
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
