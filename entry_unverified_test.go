package rarengine

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// assertUnverifiable pins the full contract of a member that produced bytes
// nothing could be compared against: the content is delivered, and BOTH Read
// and Close report ErrChecksumUnsupported carrying reason.
//
// Both are asserted rather than "whichever was non-nil". Entry records one
// terminal verdict that Read returns and Close repeats, so a nil from either
// is a defect -- and a test that falls back from one to the other would pass
// while half the contract was broken.
func assertUnverifiable(t *testing.T, e *Entry, wantContent, wantReason string) {
	t.Helper()

	got, readErr := io.ReadAll(e)
	closeErr := e.Close()

	// The content is still delivered. Unverifiable is reported, not refused:
	// the caller gets the bytes and the caveat, and decides its own policy.
	if string(got) != wantContent {
		t.Fatalf("content = %q, want %q", got, wantContent)
	}
	for _, c := range []struct {
		what string
		err  error
	}{{"Read", readErr}, {"Close", closeErr}} {
		if !errors.Is(c.err, ErrChecksumUnsupported) {
			t.Fatalf("%s = %v, want ErrChecksumUnsupported", c.what, c.err)
		}
		// The reason is the helper's only job: the verdict is identical across
		// every unverifiable class, so a wrong reason is silent unless asserted.
		if !strings.Contains(c.err.Error(), wantReason) {
			t.Fatalf("%s = %q, want it to name the reason %q", c.what, c.err, wantReason)
		}
	}
}

// TestBlake2spOnlyMemberReportsUnverifiable is the fixture-backed half of the
// silent path: a real archive written with `rar -htb` carries a BLAKE2sp
// digest and no CRC32 at all.
//
// Before this, verifyChecksum's `!HasCRC32` arm returned nil, so the member
// delivered its bytes and Close reported success with nothing having been
// compared against anything. A caller could not tell that apart from a
// member whose CRC32 matched -- which is the one thing the checksum machinery
// exists to make distinguishable.
//
// Mutation check: restore `if e.size == 0 || !e.cur.HasCRC32 { return nil }`
// and this fails with a nil verdict.
func TestBlake2spOnlyMemberReportsUnverifiable(t *testing.T) {
	r := readerFor(fixtureBytes(t, "rar5_blake2.rar"))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.HasCRC32 || !e.Header.HasBlake2sp {
		t.Fatalf("fixture %q has HasCRC32=%v HasBlake2sp=%v; it no longer "+
			"exercises this path", e.Header.Name, e.Header.HasCRC32, e.Header.HasBlake2sp)
	}
	assertUnverifiable(t, e, "hello rardecode", "records only a BLAKE2sp digest")
}

// A member carrying no digest of any kind is the same verdict. Nothing was
// checked, whether that is because the digest is one we cannot compute or
// because the archive recorded none -- the distinction lives in the message,
// not in what the caller is told about its content.
func TestMemberWithNoDigestReportsUnverifiable(t *testing.T) {
	const content = "0123456789"
	r := readerFor(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "bare.bin", content: content})))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	assertUnverifiable(t, e, content, "records no checksum")
}

// TestUncheckableDigestNamesWhatTheHeaderActuallyRecords pins the message
// against real archives, because the message is the helper's entire purpose
// and a wrong one is invisible: every class returns the same verdict.
//
// The encrypted BLAKE2sp fixture is the case that caught the bug. UseMac says
// the recorded digest is a key-derived MAC; it does NOT say which field holds
// it, and `rar -ma5 -htb -p` sets UseMac with HasCRC32 false and HasBlake2sp
// true. Testing UseMac first reported "not a CRC32 of the plaintext" -- naming
// a field the header does not carry -- while testing HasCRC32 first would
// have dropped the MAC instead. Both facts are true, so both are reported.
func TestUncheckableDigestNamesWhatTheHeaderActuallyRecords(t *testing.T) {
	for _, tc := range []struct {
		fixture    string
		password   string
		wantReason string
	}{
		{"rar5_blake2.rar", "", "records only a BLAKE2sp digest"},
		{"rar5_encrypted.rar", "test", "records a key-derived MAC in place of a CRC32"},
		{"rar5_blake2_encrypted.rar", "test", "records a key-derived MAC over a BLAKE2sp digest"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			r := readerFor(fixtureBytes(t, tc.fixture))
			if tc.password != "" {
				r.SetPasswords([]string{tc.password})
			}
			e, err := r.NextEntry()
			if err != nil {
				t.Fatalf("NextEntry: %v", err)
			}
			t.Logf("UseMac=%v HasCRC32=%v HasBlake2sp=%v",
				e.Header.UseMac, e.Header.HasCRC32, e.Header.HasBlake2sp)
			assertUnverifiable(t, e, "hello rardecode", tc.wantReason)
		})
	}
}

// A member that produced no bytes has nothing to verify, whatever kind of
// digest its header records.
//
// The produced-size gate used to sit BELOW the UseMac test, so an empty file
// or a directory inside an encrypted archive reported ErrChecksumUnsupported
// having produced nothing at all -- a member the library could not have failed
// to verify, because there was nothing to compare. The gate now precedes every
// uncheckable-digest arm, and this pins that ordering.
//
// Built directly rather than through a fixture: rar will not produce a
// zero-byte member carrying UseMac, which is the point -- nothing stops a
// crafted archive from doing so, and the verdict must not depend on RAR's
// habits.
//
// Mutation check: move the e.size == 0 return back below the digest arms and
// this fails with ErrChecksumUnsupported.
func TestZeroLengthMemberIsCleanEvenWithAnUncheckableDigest(t *testing.T) {
	for _, tc := range []struct {
		name string
		fh   *FileHeader
	}{
		{"UseMac", &FileHeader{Name: "empty.bin", LastBlock: true, UseMac: true}},
		{"blake2sp only", &FileHeader{
			Name: "empty.bin", LastBlock: true,
			HasBlake2sp: true, Blake2sp: make([]byte, 32),
		}},
		{"no digest", &FileHeader{Name: "empty.bin", LastBlock: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := entryOver("", tc.fh).Close(); err != nil {
				t.Fatalf("Close = %v, want nil: the member produced no bytes, "+
					"so no check was missed", err)
			}
		})
	}
}

// The same holds through the public API for a real directory entry, which is
// what makes this more than a unit-level property: every archive containing a
// directory would report ErrChecksumUnsupported if the gate moved.
func TestDirectoryMemberCompletesClean(t *testing.T) {
	r := readerFor(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "dir", isDir: true})))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil: a member that produced nothing has "+
			"nothing to verify", err)
	}
}

// An unverifiable member does not damage the window, so a solid successor is
// still decoded rather than refused. finishActive excludes
// ErrChecksumUnsupported from the damage set for exactly this reason: the
// member decoded correctly as far as anyone can tell, and its history is
// whatever a solid successor's back-references expect. Making the gap
// observable must not silently convert a whole archive class into damage.
//
// solidArchiveTwoMembers builds precisely this shape -- a first member with no
// CRC32, so unverifiable, followed by a solid one that carries a digest.
func TestUnverifiableMemberDoesNotDamageTheWindow(t *testing.T) {
	r := readerFor(solidArchiveTwoMembers(t, "a.bin", "b.bin"))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	// Asserted, not tolerated: `err != nil && !errors.Is(...)` would pass on a
	// nil error, so a regression that stopped reporting the first member at
	// all would leave this test green.
	if _, err := io.ReadAll(e); !errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("first member read = %v, want ErrChecksumUnsupported", err)
	}
	_ = e.Close()

	e, err = r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("solid successor of an unverifiable member = %v; an "+
			"unverifiable digest is not window damage", err)
	}
	if !bytes.Equal(got, []byte("second member")) {
		t.Fatalf("solid successor content = %q", got)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("solid successor Close = %v", err)
	}
}
