package rarengine

import (
	"errors"
	"io"
	"testing"
)

// TestSolidFileHeaderInANonSolidArchiveIsRefused pins the invariant that
// solid is archive-level: a file header that says solid in an archive header
// that does not is refused as ErrSolidFlagMismatch, before the window is
// touched.
//
// The second case is the shape the PR review found: a stored member, then a
// solid successor. Without the refusal the stored member recorded nothing
// (the archive is not solid) while BeginFile(true) kept the history, so the
// successor read a window nothing had written.
func TestSolidFileHeaderInANonSolidArchiveIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		members [][]byte
		victim  string
	}{
		{
			name: "first member",
			members: [][]byte{
				rar5Member(t, memberSpec{name: "solid.bin", content: "hello", solid: true, withCRC: true}),
			},
			victim: "solid.bin",
		},
		{
			name: "stored member then solid successor",
			members: [][]byte{
				rar5Member(t, memberSpec{name: "plain.bin", content: "plain", withCRC: true}),
				rar5Member(t, memberSpec{name: "solid.bin", content: "hello", solid: true, withCRC: true}),
			},
			victim: "solid.bin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(volumesOf(rar5Archive(t, false, tc.members...)))
			defer r.Close() //nolint:errcheck

			var e *Entry
			for {
				next, err := r.NextEntry()
				if err != nil {
					t.Fatalf("NextEntry before %q: %v", tc.victim, err)
				}
				if next.Header.Name == tc.victim {
					e = next
					break
				}
				if _, err := io.Copy(io.Discard, next); err != nil {
					t.Fatalf("reading %q: %v", next.Header.Name, err)
				}
			}
			n, err := e.Read(make([]byte, 16))
			if n != 0 || !errors.Is(err, ErrSolidFlagMismatch) {
				t.Fatalf("Read = (%d, %v), want (0, ErrSolidFlagMismatch)", n, err)
			}
			if err := e.Close(); !errors.Is(err, ErrSolidFlagMismatch) {
				t.Fatalf("Close = %v, want ErrSolidFlagMismatch", err)
			}
			if errors.Is(err, ErrCorruptArchiveHeader) {
				t.Fatal("a member-level refusal must not look like an archive-level one")
			}
		})
	}
}

// TestArchiveHeaderSolidFlagFlipAcrossVolumes pins that every volume repeats
// the archive header and they must agree: the flag is no longer a sticky OR,
// which let volume 2 switch solidity on after a member's chain had been built
// without history recording. Both directions, because a sticky OR hid only one.
func TestArchiveHeaderSolidFlagFlipAcrossVolumes(t *testing.T) {
	for _, firstSolid := range []bool{false, true} {
		const content = "hello world"
		half := len(content) / 2
		v1 := rar5Archive(t, firstSolid, rar5Member(t, memberSpec{
			name: "split.bin", content: content[:half],
			unpackedSz: new(int64(len(content))), packedSz: new(int64(half)), notLast: true,
		}))
		v2 := rar5Archive(t, !firstSolid, rar5Member(t, memberSpec{
			name: "split.bin", content: content[half:],
			unpackedSz: new(int64(len(content))), packedSz: new(int64(len(content) - half)),
			notFirst: true, withCRC: true, crcOf: content,
		}))

		r := NewReader(volumesOf(v1, v2))
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("firstSolid=%v: NextEntry: %v", firstSolid, err)
		}
		_, err = io.ReadAll(e)
		if !errors.Is(err, ErrCorruptArchiveHeader) {
			t.Fatalf("firstSolid=%v: ReadAll = %v, want ErrCorruptArchiveHeader", firstSolid, err)
		}
		if _, err := r.NextEntry(); !errors.Is(err, ErrCorruptArchiveHeader) {
			t.Fatalf("firstSolid=%v: NextEntry after = %v, want the latched ErrCorruptArchiveHeader",
				firstSolid, err)
		}
		_ = r.Close()
	}
}

// TestResetForgetsTheSolidFlagItSaw pins that Reset clears the "seen" marker
// with the flag: a Reader reused for a non-solid archive after a solid one
// must not compare the new archive's header against the old one's. The first
// archive is the NON-solid one because Reset zeroes r.solid, so only a solid
// successor differs from what a stale marker would compare against.
func TestResetForgetsTheSolidFlagItSaw(t *testing.T) {
	member := rar5Member(t, memberSpec{name: "a.bin", content: "hello", withCRC: true})
	r := NewReader(volumesOf(rar5Archive(t, false, member)))
	if _, err := r.NextEntry(); err != nil {
		t.Fatalf("non-solid archive NextEntry: %v", err)
	}
	r.Reset(volumesOf(rar5Archive(t, true, member)))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after Reset: %v", err)
	}
	if _, err := io.ReadAll(e); err != nil {
		t.Fatalf("ReadAll after Reset: %v", err)
	}
	if !r.solid {
		t.Fatal("r.solid not set by the solid archive read after Reset")
	}
}

// TestContinuationChangingSolidIsRefused pins the continuation identity check:
// the archive is solid throughout and the first block is not flagged, but the
// continuation is. dispatch admitted the first block against its own flag, so
// a continuation disagreeing has contradicted what that admission relied on.
func TestContinuationChangingSolidIsRefused(t *testing.T) {
	const content = "hello world"
	half := len(content) / 2
	v1 := rar5Archive(t, true, rar5Member(t, memberSpec{
		name: "split.bin", content: content[:half],
		unpackedSz: new(int64(len(content))), packedSz: new(int64(half)), notLast: true,
	}))
	v2 := rar5Archive(t, true, rar5Member(t, memberSpec{
		name: "split.bin", content: content[half:],
		unpackedSz: new(int64(len(content))), packedSz: new(int64(len(content) - half)),
		notFirst: true, solid: true, withCRC: true, crcOf: content,
	}))
	r := NewReader(volumesOf(v1, v2))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if _, err := io.ReadAll(e); !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("ReadAll = %v, want ErrCorruptFileHeader", err)
	}
}
