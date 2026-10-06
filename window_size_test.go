package rarengine

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// The window starts at the format minimum and grows to what each member's
// header declares, so an archive made with -md64m or -md1g decodes instead of
// ending short at 32 MiB. The fixtures are real rar output with one tiny
// member each (see generate.sh for the -si trick that keeps rar from shrinking
// the dictionary to the input), so this pins the reservation, not the decode.
func TestWindowGrowsToTheDeclaredDictionary(t *testing.T) {
	cases := []struct {
		fixture string
		dict    int64
	}{
		{"rar5_dict_128k.rar", 128 << 10},
		{"rar5_dict_1m.rar", 1 << 20},
		{"rar5_dict_32m.rar", 32 << 20},
		{"rar5_dict_64m.rar", 64 << 20},
		{"rar5_dict_1g.rar", 1 << 30},
		{"rar5_dict4g.rar", 4 << 30},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			r := NewReader(fileVolumesOf(t, filepath.Join("testdata", tc.fixture)))
			defer r.Close() //nolint:errcheck
			if r.win.size != minWindowSize {
				t.Fatalf("fresh Reader window = %d, want the %d minimum", r.win.size, minWindowSize)
			}
			e, err := r.NextEntry()
			if err != nil {
				t.Fatalf("NextEntry: %v", err)
			}
			if e.Header.DictSize != tc.dict {
				t.Fatalf("DictSize = %d, want %d", e.Header.DictSize, tc.dict)
			}
			want := int(max(tc.dict, minWindowSize))
			if r.win.size != want {
				t.Fatalf("window after admission = %d, want %d", r.win.size, want)
			}
			if _, err := io.Copy(io.Discard, e); err != nil {
				t.Fatalf("Read: %v", err)
			}
			if err := e.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

// SetMaxWindow is the one thing that keeps a window below the declaration. A
// member whose stream fits the cap still decodes; one that reaches past it is
// ErrDictionaryTooLarge, which TestFarReferenceReportsDictionaryTooLarge pins
// on a real stream.
func TestSetMaxWindowCapsTheWindow(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_64m.rar")))
	defer r.Close() //nolint:errcheck
	r.SetMaxWindow(1 << 20)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if r.win.size != 1<<20 {
		t.Fatalf("window = %d, want the 1 MiB cap", r.win.size)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("a member whose stream fits the cap must still decode: %v", err)
	}
}

// windowBacking.free runs the release exactly once however many callers
// reach it: grow frees the reservation it replaces, and the cleanup registered
// for that same reservation fires later for a window nobody holds any more.
func TestWindowBackingFreesExactlyOnce(t *testing.T) {
	n := 0
	b := &windowBacking{release: func() { n++ }}
	for range 3 {
		b.free()
	}
	if n != 1 {
		t.Fatalf("release ran %d times, want 1", n)
	}
	var nilBacking *windowBacking
	nilBacking.free() // a window that never grew has nothing to free
}

// A stored member in a non-solid archive is served from its source and never
// touches the window, so it must not cost a reservation either: this is what
// lets a Reader verify a stored video with the window at its starting size.
func TestStoredMemberInNonSolidArchiveDoesNotGrowTheWindow(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_store.rar")))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.Method != 0 {
		t.Fatalf("fixture member has Method %d, want stored", e.Header.Method)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if r.win.size != minWindowSize || r.win.backing != nil {
		t.Fatalf("window = %d bytes, backing %v; want the %d minimum with no reservation",
			r.win.size, r.win.backing != nil, minWindowSize)
	}
}

// Growing discards history the way a non-solid member's BeginFile would, so a
// solid member -- whose back-references assume that history -- cannot be the
// one to grow it. rar gives every member of a solid archive the archive's
// dictionary, so a solid member declaring more than the window the archive
// established is a corrupt header.
func TestSolidMemberDeclaringALargerDictionaryIsRefused(t *testing.T) {
	first := rar5Member(t, memberSpec{name: "a.bin", content: "first member", withCRC: true})
	// e = 8: 128 KiB << 8 = 32 MiB, far more than the 256 KiB the first
	// member left the window at.
	grown := rar5Member(t, memberSpec{name: "b.bin", content: "second", withCRC: true,
		solid: true, extraCompFlags: 8 << fileCompDictShift})
	r := NewReader(volumesOf(rar5Archive(t, true, first, grown)))
	defer r.Close() //nolint:errcheck

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("first member: %v", err)
	}
	e, err = r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if e.Header.DictSize != 32<<20 {
		t.Fatalf("second member DictSize = %d, want 32 MiB", e.Header.DictSize)
	}
	if _, err := io.Copy(io.Discard, e); !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("solid member declaring a larger dictionary: Read = %v, want ErrCorruptFileHeader", err)
	}
	if r.win.size != minWindowSize {
		t.Fatalf("refused member grew the window to %d", r.win.size)
	}
}

// sizeWindow's decision table, driven directly: who grows the window, who is
// exempt, who is refused, and what the cap does. The synthetic builder only
// writes stored members, so the compressed cases are stated as headers.
func TestSizeWindowDecisionTable(t *testing.T) {
	cases := []struct {
		name      string
		solidArc  bool
		fh        FileHeader
		max       int64
		wantSize  int
		wantErr   error
		startSize int
	}{
		{name: "compressed non-solid grows", fh: FileHeader{Method: 3, DictSize: 1 << 20}, wantSize: 1 << 20},
		{name: "stored in non-solid archive is exempt", fh: FileHeader{Method: 0, DictSize: 1 << 20}, wantSize: minWindowSize},
		{name: "stored in solid archive grows", solidArc: true, fh: FileHeader{Method: 0, DictSize: 1 << 20}, wantSize: 1 << 20},
		{name: "no declaration leaves the window alone", fh: FileHeader{Method: 3}, wantSize: minWindowSize},
		{name: "declaration within the window is a no-op", fh: FileHeader{Method: 3, DictSize: 128 << 10}, wantSize: minWindowSize},
		{name: "cap bounds growth", fh: FileHeader{Method: 3, DictSize: 64 << 20}, max: 1 << 20, wantSize: 1 << 20},
		{name: "solid member needing growth is refused", solidArc: true,
			fh: FileHeader{Name: "b", Method: 3, DictSize: 1 << 20, Solid: true}, wantSize: minWindowSize, wantErr: ErrCorruptFileHeader},
		{name: "solid member within the window is fine", solidArc: true, startSize: 1 << 20,
			fh: FileHeader{Method: 3, DictSize: 1 << 20, Solid: true}, wantSize: 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(make(chan io.ReadCloser))
			defer r.Close() //nolint:errcheck
			r.solid = tc.solidArc
			if tc.max != 0 {
				r.SetMaxWindow(tc.max)
			}
			if tc.startSize != 0 {
				if err := r.win.grow(tc.startSize); err != nil {
					t.Fatal(err)
				}
			}
			err := r.sizeWindow(&tc.fh)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("sizeWindow = %v, want %v", err, tc.wantErr)
			}
			if r.win.size != tc.wantSize {
				t.Fatalf("window = %d, want %d", r.win.size, tc.wantSize)
			}
		})
	}
}

// A continuation block declaring a different dictionary than its first block
// is refused like a continuation changing its method, version or solid flag:
// the window was sized and the classification is read from the first block.
func TestContinuationChangingDictSizeIsRefused(t *testing.T) {
	const content = "hello world"
	half := len(content) / 2
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: content[:half],
		unpackedSz: new(int64(len(content))), packedSz: new(int64(half)), notLast: true,
	}))
	v2 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: content[half:],
		unpackedSz: new(int64(len(content))), packedSz: new(int64(len(content) - half)),
		notFirst: true, withCRC: true, crcOf: content,
		extraCompFlags: 5 << fileCompDictShift,
	}))
	r := NewReader(volumesOf(v1, v2))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	_, err = io.ReadAll(e)
	if !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("ReadAll = %v, want ErrCorruptFileHeader", err)
	}
	// Four identity checks share the sentinel; the message says which fired.
	if !strings.Contains(err.Error(), "dictionary") {
		t.Fatalf("refusal did not come from the dictionary check: %v", err)
	}
}

// grow is a storage operation with BeginFile(false)'s effect on history, and
// a no-op when the window is already large enough.
func TestWindowGrowDiscardsHistoryAndNeverShrinks(t *testing.T) {
	w := newWindow(minWindowSize)
	w.writeBytes([]byte("some history"))
	w.r = w.w
	if w.historyLen() == 0 {
		t.Fatal("setup: no history")
	}

	if err := w.grow(minWindowSize / 2); err != nil {
		t.Fatalf("grow smaller: %v", err)
	}
	if w.size != minWindowSize || w.historyLen() == 0 || w.backing != nil {
		t.Fatal("a grow to a smaller size must keep the buffer and its history")
	}

	if err := w.grow(1 << 20); err != nil {
		t.Fatalf("grow: %v", err)
	}
	if w.size != 1<<20 || len(w.buf) != 1<<20 {
		t.Fatalf("size = %d, len(buf) = %d, want 1 MiB", w.size, len(w.buf))
	}
	if w.historyLen() != 0 || w.w != 0 || w.r != 0 || w.wrapped || w.full {
		t.Fatalf("grow kept history: w=%d r=%d wrapped=%v full=%v", w.w, w.r, w.wrapped, w.full)
	}
	if w.backing == nil {
		t.Fatal("grown window has no backing to release")
	}
	// The new buffer is usable end to end and reads as zero where untouched.
	w.buf[0], w.buf[w.size-1] = 1, 2
	if w.buf[w.size/2] != 0 {
		t.Fatal("reserved window is not zero-filled")
	}

	first := w.backing
	if err := w.grow(2 << 20); err != nil {
		t.Fatalf("second grow: %v", err)
	}
	if w.backing == first {
		t.Fatal("second grow kept the first reservation")
	}
	// Releasing the replaced reservation twice is harmless: grow freed it,
	// and the cleanup registered for it will call free again.
	first.free()
	first.free()

	// decommit keeps the size and the reservation.
	w.writeBytes([]byte("x"))
	w.Reset(false)
	w.decommit()
	if w.size != 2<<20 || w.backing == nil {
		t.Fatal("decommit changed the window's size or dropped its reservation")
	}
	w.writeBytes([]byte("still writable"))
	if w.historyLen() != len("still writable") {
		t.Fatal("window not writable after decommit")
	}
}

// The fill target is half the window up to a fixed cap: the shipped 32 MiB
// window keeps its 16 MiB target exactly, and a 4 GiB window does not stage
// 2 GiB before serving a byte.
func TestFillTargetIsHalfTheWindowUpToACap(t *testing.T) {
	cases := []struct{ size, want int }{
		{minWindowSize, minWindowSize / 2},
		{1 << 20, 1 << 19},
		{32 << 20, 16 << 20},
		{64 << 20, 16 << 20},
		{4 << 30, 16 << 20},
	}
	for _, tc := range cases {
		w := &window{size: tc.size}
		if got := w.fillTarget(); got != tc.want {
			t.Errorf("fillTarget for %d = %d, want %d", tc.size, got, tc.want)
		}
	}
}

// Reset keeps the grown window: the next archive reuses the reservation, and
// a smaller declaration does not shrink it.
func TestResetKeepsTheGrownWindow(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_64m.rar")))
	defer r.Close() //nolint:errcheck
	if _, err := r.NextEntry(); err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if r.win.size != 64<<20 {
		t.Fatalf("window = %d, want 64 MiB", r.win.size)
	}
	r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_1m.rar")))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after Reset: %v", err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("Read after Reset: %v", err)
	}
	if r.win.size != 64<<20 {
		t.Fatalf("window after Reset = %d, want the 64 MiB kept", r.win.size)
	}
}
