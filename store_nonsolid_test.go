package rarengine

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestNonSolidArchiveStoredMemberLeavesWindowUntouched exercises the buildChain
// logic end-to-end: opening a real non-solid fixture with a stored member through
// NewReader and verifying the window is not touched during decompression.
//
// This exercises the actual buildChain branch: Reader.solid is false, so a nil
// window is passed to storeReader instead of r.win. The test validates that the
// window pointers remain at their initial state after reading the stored member.
//
// Mutation check: remove the r.solid check in buildChain (make it always pass
// r.win), and this test fails because the window will be dirtied by recordHistory.
func TestNonSolidArchiveStoredMemberLeavesWindowUntouched(t *testing.T) {
	// rar5_store.rar is a non-solid archive with a single stored member
	f, err := os.Open(filepath.Join("testdata", "rar5_store.rar"))
	if err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	defer f.Close() //nolint:errcheck

	volChan := make(chan io.ReadCloser, 1)
	volChan <- f
	close(volChan)

	r := NewReader(volChan)
	defer r.Close() //nolint:errcheck

	// Verify the archive is non-solid
	if r.solid {
		t.Fatal("fixture is solid; test needs a non-solid archive")
	}

	// Capture initial window state
	initialHistLen := r.win.historyLen()
	initialW := r.win.w
	initialR := r.win.r
	initialWrapped := r.win.wrapped

	// Read the stored member
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	defer e.Close() //nolint:errcheck

	if e.Header.Method != 0 {
		t.Fatalf("fixture member has Method=%d, want 0 (stored)", e.Header.Method)
	}

	// Read all content
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("Read member: %v", err)
	}

	// Window must remain completely untouched by the stored member
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

// TestBuildChainGivesStoreReaderTheWindowOnlyWhenSolid directly tests the
// buildChain decision logic: when the archive is solid, storeReader gets r.win;
// when non-solid, it gets nil.
//
// This test constructs a Reader and directly manipulates r.solid to test both
// branches, exercising the conditional that neither existing test reaches.
//
// Mutation checks:
// (a) Make buildChain always pass r.win: solid=false case fails because s.win != nil
// (b) Make buildChain always pass nil: solid=true case fails because s.win != r.win
func TestBuildChainGivesStoreReaderTheWindowOnlyWhenSolid(t *testing.T) {
	// Construct a Reader with a dummy volume channel, the way other tests do
	r := NewReader(make(chan io.ReadCloser))
	defer r.Close() //nolint:errcheck

	// Minimal FileHeader for a stored member
	fh := &FileHeader{
		Name:   "test.bin",
		Method: 0, // stored
	}
	payload := bytes.NewReader([]byte("test data"))

	// Test case 1: non-solid archive (r.solid = false)
	r.solid = false
	src, err := r.buildChain(fh, payload)
	if err != nil {
		t.Fatalf("buildChain non-solid: %v", err)
	}

	sr, ok := src.(*storeReader)
	if !ok {
		t.Fatalf("buildChain non-solid returned %T, want *storeReader", src)
	}
	if sr.win != nil {
		t.Error("non-solid: storeReader.win should be nil, got non-nil")
	}

	// Test case 2: solid archive (r.solid = true)
	r.solid = true
	payload.Reset([]byte("test data"))
	src, err = r.buildChain(fh, payload)
	if err != nil {
		t.Fatalf("buildChain solid: %v", err)
	}

	sr, ok = src.(*storeReader)
	if !ok {
		t.Fatalf("buildChain solid returned %T, want *storeReader", src)
	}
	if sr.win != r.win {
		t.Errorf("solid: storeReader.win should be r.win (%p), got %p", r.win, sr.win)
	}
}
