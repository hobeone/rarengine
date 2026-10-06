package rarengine

import (
	"io"
	"path/filepath"
	"testing"
)

// rar5_solid_stored_mid.rar is rar's own output for
//
//	rar a -s -ds -msjpg ... a_first.txt b_stored.jpg c_after.txt
//
// a compressed member, a stored one carrying the solid flag, and a compressed
// solid member whose stream back-references a_first.txt across the stored
// member. unrar verifies all three. Recording the stored bytes as history
// shifted every one of those references and c_after.txt failed its CRC (#94).
// Mutation check: record the stored member's bytes into the window again and
// the third member reports ErrCRCMismatch.
func TestSolidSuccessorAfterStoredMemberDecodes(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_stored_mid.rar")))
	defer r.Close() //nolint:errcheck
	want := []struct {
		name   string
		method int
		size   int64
	}{
		{"in/a_first.txt", 3, 24004},
		{"in/b_stored.jpg", 0, 6000},
		{"in/c_after.txt", 3, 24004},
	}
	for _, m := range want {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry %s: %v", m.name, err)
		}
		if e.Header.Name != m.name || e.Header.Method != m.method {
			t.Fatalf("got %s method %d, want %s method %d", e.Header.Name, e.Header.Method, m.name, m.method)
		}
		n, err := io.Copy(io.Discard, e)
		if err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if n != m.size {
			t.Fatalf("%s: %d bytes, want %d", m.name, n, m.size)
		}
	}
	if _, err := r.NextEntry(); err != io.EOF {
		t.Fatalf("after the last member: %v, want io.EOF", err)
	}
}

// The inverse of the claim the old code was built on: a solid member cannot
// see a stored predecessor's bytes, because they never entered the window.
// Two stored members in a solid archive leave the history empty.
func TestSolidSuccessorDoesNotSeeStoredBytes(t *testing.T) {
	first := rar5Member(t, memberSpec{name: "a.bin", content: "stored bytes, never history", withCRC: true})
	second := rar5Member(t, memberSpec{name: "b.bin", content: "more of the same", withCRC: true, solid: true})
	r := NewReader(volumesOf(rar5Archive(t, true, first, second)))
	defer r.Close() //nolint:errcheck
	for _, name := range []string{"a.bin", "b.bin"} {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry %s: %v", name, err)
		}
		if _, err := io.Copy(io.Discard, e); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := r.win.historyLen(); got != 0 {
			t.Fatalf("after %s the window holds %d bytes of history, want 0", name, got)
		}
	}
	if !r.solid {
		t.Fatal("setup: the archive is not solid, so the test exercises nothing")
	}
}
