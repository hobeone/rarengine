package rarengine

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"
)

// A stored member in a non-solid archive leaves the window untouched: the
// window pointers are what they were before the member was read. (The solid
// case is TestSolidSuccessorDoesNotSeeStoredBytes.)
func TestNonSolidArchiveStoredMemberLeavesWindowUntouched(t *testing.T) {
	// rar5_store.rar is a non-solid archive with a single stored member
	volChan := fileVolumesOf(t, filepath.Join("testdata", "rar5_store.rar"))

	r := NewReader(volChan)
	defer r.Close() //nolint:errcheck

	initialHistLen := r.win.historyLen()
	initialW := r.win.w
	initialR := r.win.r
	initialWrapped := r.win.wrapped

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	defer e.Close() //nolint:errcheck

	if r.solid {
		t.Fatal("fixture is solid; test needs a non-solid archive")
	}
	if e.Header.Method != 0 {
		t.Fatalf("fixture member has Method=%d, want 0 (stored)", e.Header.Method)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("Read member: %v", err)
	}

	if got := r.win.historyLen(); got != initialHistLen {
		t.Errorf("historyLen changed from %d to %d: window was dirtied by "+
			"non-solid stored member", initialHistLen, got)
	}
	if got := r.win.w; got != initialW {
		t.Errorf("write pointer changed from %d to %d: window was dirtied",
			initialW, got)
	}
	if got := r.win.r; got != initialR {
		t.Errorf("read pointer changed from %d to %d: window was dirtied",
			initialR, got)
	}
	if got := r.win.wrapped; got != initialWrapped {
		t.Errorf("wrapped changed from %v to %v: window was dirtied",
			initialWrapped, got)
	}
}

// buildChain hands a stored member its source directly, whatever the
// archive's solidity: there is no window-recording wrapper left to give it.
// Mutation check: wrap the source in anything and the identity fails.
func TestBuildChainReturnsTheSourceForAStoredMember(t *testing.T) {
	r := NewReader(make(chan io.ReadCloser))
	defer r.Close() //nolint:errcheck
	fh := &FileHeader{Name: "test.bin", Method: 0}
	payload := bytes.NewReader([]byte("test data"))
	for _, solid := range []bool{false, true} {
		r.solid = solid
		src, err := r.buildChain(fh, payload)
		if err != nil {
			t.Fatalf("buildChain solid=%v: %v", solid, err)
		}
		if src != io.Reader(payload) {
			t.Fatalf("buildChain solid=%v returned %T, want the source itself", solid, src)
		}
	}
}
