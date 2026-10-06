package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// oldCopyBytesAccepts is an independent transcription of the predicate
// CopyBytes had before ErrDictionaryTooLarge existed. It is written against
// the test's own model of how much history a file has produced, never against
// window.historyLen, so that a change to either shows up as a disagreement.
func oldCopyBytesAccepts(modelHistory, distance int) bool {
	return distance > 0 && distance <= modelHistory
}

// windowScenario builds a window in a named state and returns it with the
// number of history bytes the test's own bookkeeping says it holds.
type windowScenario struct {
	name  string
	build func(w *window) (modelHistory int)
}

func scenarios(size int) []windowScenario {
	fill := func(w *window, n int) {
		for range n {
			w.writeByte(byte(w.w))
		}
		// Drain so full/Available stay unremarkable; only history matters here.
		w.r = w.w
		w.full = false
	}
	return []windowScenario{
		{"fresh", func(w *window) int { return 0 }},
		{"partial", func(w *window) int { fill(w, 1000); return 1000 }},
		{"one short of full", func(w *window) int { fill(w, size-1); return size - 1 }},
		{"exactly full", func(w *window) int { fill(w, size); return size }},
		{"wrapped", func(w *window) int { fill(w, size+777); return size }},
		{"wrapped twice", func(w *window) int { fill(w, 2*size+5); return size }},
		{"solid reuse of partial history", func(w *window) int {
			fill(w, 5000)
			if err := w.BeginFile(true); err != nil {
				panic(err)
			}
			fill(w, 3000)
			return 8000
		}},
		{"solid reuse of full history", func(w *window) int {
			fill(w, size+10)
			if err := w.BeginFile(true); err != nil {
				panic(err)
			}
			fill(w, 10)
			return size
		}},
		{"non-solid after full history", func(w *window) int {
			fill(w, size+10)
			if err := w.BeginFile(false); err != nil {
				panic(err)
			}
			fill(w, 4000)
			return 4000
		}},
		{"non-solid reset leaves nothing", func(w *window) int {
			fill(w, size+10)
			if err := w.BeginFile(false); err != nil {
				panic(err)
			}
			return 0
		}},
	}
}

// The set of distances CopyBytes accepts must be exactly the set it accepted
// before the dictionary classification existed: the bound is what keeps the
// deliberately uncleared window from being readable across files. Only which
// error a refusal reports may change.
//
// Exhaustive over 0..size+2 for every state (restoring the window after each
// call, so an accepted copy does not move the state under the next distance),
// plus the extremes an attacker can name.
func TestCopyBytesAcceptsExactlyTheOldPredicate(t *testing.T) {
	const size = 0x40000
	extremes := []int{-1 << 31, -size, -1, math.MaxInt32, math.MaxInt32 - 1, 1 << 30, 3 << 29}
	for _, sc := range scenarios(size) {
		t.Run(sc.name, func(t *testing.T) {
			w := newWindow(size)
			hist := sc.build(w)
			if got := w.historyLen(); got != hist {
				t.Fatalf("scenario is wrong: historyLen() = %d, model says %d", got, hist)
			}
			saved := *w
			// A decoder declaring a dictionary far larger than the window, so
			// that every refusal that CAN be reported as capacity is.
			d := &decoder50{dictSize: 1 << 32}

			check := func(distance int) {
				want := oldCopyBytesAccepts(hist, distance)

				*w = saved
				err := w.CopyBytes(1, distance)
				if (err == nil) != want {
					t.Fatalf("CopyBytes(1, %d): err = %v, old predicate accepts = %v", distance, err, want)
				}
				if err != nil && !errors.Is(err, ErrWindowOffsetBounds) {
					t.Fatalf("CopyBytes(1, %d) = %v, want ErrWindowOffsetBounds", distance, err)
				}
				if err != nil && (w.r != saved.r || w.w != saved.w || w.full != saved.full || w.wrapped != saved.wrapped) {
					t.Fatalf("refused CopyBytes(1, %d) moved the window", distance)
				}

				*w = saved
				d.length, d.offset[0] = 1, distance
				cerr := d.copyMatch(w)
				if (cerr == nil) != want {
					t.Fatalf("copyMatch(distance %d): err = %v, old predicate accepts = %v", distance, cerr, want)
				}
				if cerr != nil && !errors.Is(cerr, ErrWindowOffsetBounds) {
					t.Fatalf("copyMatch(distance %d) = %v, want it to still be ErrWindowOffsetBounds", distance, cerr)
				}
				if cerr != nil && errors.Is(cerr, io.EOF) {
					t.Fatalf("copyMatch(distance %d) = %v satisfies io.EOF", distance, cerr)
				}
				// The classification, restated independently of copyMatch.
				wantCapacity := !want && hist == size && distance > size
				if got := errors.Is(cerr, ErrDictionaryTooLarge); got != wantCapacity {
					t.Fatalf("copyMatch(distance %d) ErrDictionaryTooLarge = %v, want %v (history %d)",
						distance, got, wantCapacity, hist)
				}
			}
			for distance := 0; distance <= size+2; distance++ {
				check(distance)
			}
			for _, distance := range extremes {
				check(distance)
			}
		})
	}
}

// Assumption: once a file has produced a window's worth of history,
// historyLen() is exactly the window size, whichever write path got it there.
// The classification's first gate leans on that, so it is shown on the real
// type through every path that advances w rather than asserted.
func TestFullWindowHasHistoryLenEqualToSize(t *testing.T) {
	const size = 0x40000
	cases := map[string]func(w *window){
		"writeByte": func(w *window) {
			for range size {
				w.writeByte(1)
			}
		},
		"writeBytes":    func(w *window) { w.writeBytes(make([]byte, size)) },
		"recordHistory": func(w *window) { w.recordHistory(make([]byte, size)) },
		"CopyBytes": func(w *window) {
			w.writeByte(1)
			if err := w.CopyBytes(size-1, 1); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, fill := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWindow(size)
			fill(w)
			if got := w.historyLen(); got != size {
				t.Fatalf("after exactly one window of output, historyLen() = %d, want %d", got, size)
			}
			// And one byte short is not full.
			w2 := newWindow(size)
			w2.writeBytes(make([]byte, size-1))
			if got := w2.historyLen(); got != size-1 {
				t.Fatalf("one byte short: historyLen() = %d, want %d", got, size-1)
			}
		})
	}
}

// The classification matrix. size is the test window's, so "larger than the
// window" is a declared dictionary of 2*size and "fits" is size itself.
func TestDictionaryClassificationMatrix(t *testing.T) {
	const size = 0x40000
	type histState struct {
		name  string
		build func(w *window)
		hist  int
	}
	fillTo := func(n int) func(w *window) {
		return func(w *window) {
			w.writeBytes(make([]byte, n))
			w.r = w.w
			w.full = false
		}
	}
	states := []histState{
		{"empty", fillTo(0), 0},
		{"partial", fillTo(1000), 1000},
		{"exactly full", fillTo(size), size},
		{"wrapped", fillTo(size + 123), size},
	}
	type distKind struct {
		name string
		pick func(hist int) int // 0 means the kind does not exist for this state
	}
	dists := []distKind{
		{"within history", func(h int) int {
			if h == 0 {
				return 0
			}
			return h
		}},
		{"past history within window", func(h int) int {
			if h+1 > size {
				return 0
			}
			return h + 1
		}},
		{"past window", func(h int) int { return size + 1 }},
	}
	for _, st := range states {
		for _, dk := range dists {
			distance := dk.pick(st.hist)
			if distance == 0 {
				continue
			}
			for _, declared := range []int64{size, 2 * size} {
				name := fmt.Sprintf("%s/%s/declared %d", st.name, dk.name, declared)
				t.Run(name, func(t *testing.T) {
					w := newWindow(size)
					st.build(w)
					d := &decoder50{dictSize: declared}
					d.length, d.offset[0] = 1, distance
					err := d.copyMatch(w)

					accepted := distance <= st.hist
					if accepted {
						if err != nil {
							t.Fatalf("distance within history refused: %v", err)
						}
						return
					}
					if err == nil {
						t.Fatalf("distance %d beyond history %d accepted", distance, st.hist)
					}
					if !errors.Is(err, ErrWindowOffsetBounds) {
						t.Fatalf("err = %v, must always satisfy ErrWindowOffsetBounds", err)
					}
					if errors.Is(err, io.EOF) {
						t.Fatalf("err = %v satisfies io.EOF", err)
					}
					wantCapacity := st.hist == size && distance > size && declared > size
					if got := errors.Is(err, ErrDictionaryTooLarge); got != wantCapacity {
						t.Fatalf("ErrDictionaryTooLarge = %v, want %v (err %v)", got, wantCapacity, err)
					}
					if wantCapacity {
						for _, n := range []int64{int64(distance), size, declared} {
							if !strings.Contains(err.Error(), fmt.Sprint(n)) {
								t.Errorf("message %q does not name %d", err, n)
							}
						}
					}
				})
			}
		}
	}
}

// A zero-distance match (offset[0] never set) and a decoder driven with no
// declared dictionary are corruption, never capacity, even on a full window.
func TestDictionaryClassificationDefaultsToCorruption(t *testing.T) {
	const size = 0x40000
	w := newWindow(size)
	w.writeBytes(make([]byte, size))
	w.r, w.full = w.w, false

	d := &decoder50{length: 1}
	d.offset[0] = size + 1 // past the window, history full, but nothing declared
	if err := d.copyMatch(w); errors.Is(err, ErrDictionaryTooLarge) || !errors.Is(err, ErrWindowOffsetBounds) {
		t.Fatalf("undeclared dictionary: err = %v, want ErrWindowOffsetBounds alone", err)
	}
	d.dictSize = 2 * size
	d.offset[0] = 0
	if err := d.copyMatch(w); errors.Is(err, ErrDictionaryTooLarge) || !errors.Is(err, ErrWindowOffsetBounds) {
		t.Fatalf("zero distance: err = %v, want ErrWindowOffsetBounds alone", err)
	}
}

// A distance past even the dictionary the header declared contradicts that
// header, so no larger window would have made the stream valid: it is
// corruption, not a capacity limit, however large the declared dictionary is.
// The classification must not claim the library could have decoded it.
func TestDictionaryClassificationBoundedByDeclaredDictionary(t *testing.T) {
	const size = 0x40000
	w := newWindow(size)
	w.writeBytes(make([]byte, size))
	w.r, w.full = w.w, false

	d := &decoder50{length: 1, dictSize: 2 * size}
	for _, tc := range []struct {
		distance     int
		wantCapacity bool
	}{
		{size + 1, true},
		{2 * size, true}, // exactly the declared dictionary still fits it
		{2*size + 1, false},
		{4 * size, false},
	} {
		d.offset[0] = tc.distance
		err := d.copyMatch(w)
		if err == nil || !errors.Is(err, ErrWindowOffsetBounds) {
			t.Fatalf("distance %d: err = %v, want a refusal wrapping ErrWindowOffsetBounds", tc.distance, err)
		}
		if got := errors.Is(err, ErrDictionaryTooLarge); got != tc.wantCapacity {
			t.Errorf("distance %d against a declared %d: ErrDictionaryTooLarge = %v, want %v (%v)",
				tc.distance, d.dictSize, got, tc.wantCapacity, err)
		}
	}
}

// The only thing connecting a parsed header to the classifier is the line in
// buildChain that hands FileHeader.DictSize to the decoder. The tests that
// reach it through real far-reference archives need the rar binary, which CI
// does not install, so this one reads the decoder's field after admission
// instead. The second member's smaller value shows the field is reassigned
// per member rather than left at the previous member's.
func TestBuildChainHandsTheDeclaredDictionaryToTheDecoder(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_64m.rar")))
	t.Cleanup(func() { _ = r.Close() })
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if e.Header.Method == 0 {
		t.Fatalf("fixture is not a compressed member, so buildChain never reaches the decoder: %+v", e.Header)
	}
	if got := r.dec50.dictSize; got != 64<<20 {
		t.Fatalf("decoder dictSize after a 64 MiB member = %d, want %d", got, 64<<20)
	}

	r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_dict_128k.rar")))
	if _, err := r.NextEntry(); err != nil {
		t.Fatal(err)
	}
	if got := r.dec50.dictSize; got != 128<<10 {
		t.Fatalf("decoder dictSize after a 128 KiB member = %d, want %d (stale value from the previous member?)",
			got, 128<<10)
	}
}

// The window a SOLID member sees carries its predecessors' history, and the
// classification reads that, not the bytes the current member produced.
func TestDictionaryClassificationCountsSolidHistory(t *testing.T) {
	const size = 0x40000
	w := newWindow(size)
	w.writeBytes(make([]byte, size))
	w.r, w.full = w.w, false
	if err := w.BeginFile(true); err != nil {
		t.Fatal(err)
	}
	// The new member has produced nothing, yet the window spans its dictionary.
	d := &decoder50{length: 1, dictSize: 2 * size}
	d.offset[0] = size + 1
	if err := d.copyMatch(w); !errors.Is(err, ErrDictionaryTooLarge) {
		t.Fatalf("solid member over full inherited history: err = %v, want ErrDictionaryTooLarge", err)
	}

	// The same member non-solid has no history: corruption.
	if err := w.BeginFile(false); err != nil {
		t.Fatal(err)
	}
	if err := d.copyMatch(w); errors.Is(err, ErrDictionaryTooLarge) || !errors.Is(err, ErrWindowOffsetBounds) {
		t.Fatalf("non-solid member: err = %v, want ErrWindowOffsetBounds alone", err)
	}
}

func TestFileHeaderDictSizeAgainstRealArchives(t *testing.T) {
	// Expected values are what `unrar lt` reports for each archive (-md=...).
	cases := []struct {
		file string
		want int64
	}{
		{"rar5_dict_128k.rar", 128 << 10},
		{"rar5_dict_1m.rar", 1 << 20},
		{"rar5_dict_32m.rar", 32 << 20},
		{"rar5_dict_64m.rar", 64 << 20},
		{"rar5_dict_1g.rar", 1 << 30},
		{"rar5_dict4g.rar", 4 << 30},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			r := NewReader(fileVolumesOf(t, filepath.Join("testdata", tc.file)))
			t.Cleanup(func() { _ = r.Close() })
			e, err := r.NextEntry()
			if err != nil {
				t.Fatal(err)
			}
			if e.Header.DictSize != tc.want {
				t.Fatalf("DictSize = %d, want %d", e.Header.DictSize, tc.want)
			}
		})
	}
}

// The exponent field is bits 10..13 and nothing else: every exponent maps to
// 128 KiB << e, the bits either side of the field do not leak in, and a
// version the field's layout does not apply to reports no size.
func TestFileHeaderDictSizeFieldLayout(t *testing.T) {
	parse := func(spec memberSpec) *FileHeader {
		t.Helper()
		fh, err := parseBuiltHeader(t, buildRAR5Member(spec))
		if err != nil {
			t.Fatal(err)
		}
		return fh
	}
	for e := uint64(0); e <= 15; e++ {
		want := int64(128<<10) << e
		fh := parse(memberSpec{name: "a", content: "x", extraCompFlags: e << 10})
		if fh.DictSize != want {
			t.Errorf("exponent %d: DictSize = %d, want %d", e, fh.DictSize, want)
		}
		// Method (bits 7..9), solid (bit 6) and bit 14 are neighbours.
		fh = parse(memberSpec{name: "a", content: "x", solid: true, extraCompFlags: e<<10 | 7<<7 | 1<<14})
		if fh.DictSize != want {
			t.Errorf("exponent %d with neighbouring bits set: DictSize = %d, want %d", e, fh.DictSize, want)
		}
	}
	fh := parse(memberSpec{name: "a", content: "x", unpackVersion: 1, extraCompFlags: 5 << 10})
	if fh.DictSize != 0 {
		t.Errorf("unpack version 1: DictSize = %d, want 0 (layout not interpreted)", fh.DictSize)
	}
}

// rarOrSkip locates the rar binary, skipping when it is absent.
func rarOrSkip(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("rar")
	if err != nil {
		t.Skip("rar binary not available")
	}
	return p
}

// randomThenRepeat writes 2*half bytes: half random bytes twice, so a
// compressor with a dictionary of at least half can encode the second copy as
// a single match half bytes back.
func randomThenRepeat(t *testing.T, path string, half int) {
	t.Helper()
	// Deterministic, incompressible-enough content without reading urandom.
	buf := make([]byte, half)
	x := uint64(88172645463325252)
	for i := range buf {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		buf[i] = byte(x >> 24)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Skipf("cannot create scratch file: %v", err)
	}
	defer func() { _ = f.Close() }()
	for range 2 {
		if _, err := f.Write(buf); err != nil {
			t.Skipf("cannot write scratch file (disk space?): %v", err)
		}
	}
}

func runRar(t *testing.T, rar, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(rar, append([]string{"a", "-inul", "-ma5", "-ep"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("rar %v failed (space?): %v\n%s", args, err, out)
	}
}

// The issue's scenario at test scale: a stream that genuinely references
// history beyond the window, with the header declaring a dictionary that
// covers it. The window is shrunk to its 256 KiB minimum so the archive is
// ~600 KB instead of 80 MB; the production-size run is below.
//
// It also pins the damage semantics: the member ends short, the verdict is
// durable, and a solid successor is refused rather than decoded against
// history the failed member never finished writing.
func TestFarReferenceReportsDictionaryTooLarge(t *testing.T) {
	rar := rarOrSkip(t)
	dir := t.TempDir()
	const half = 300000 // > the 0x40000 window, < the 1 MiB declared dictionary
	randomThenRepeat(t, filepath.Join(dir, "a_far.bin"), half)
	if err := os.WriteFile(filepath.Join(dir, "b_after.bin"), []byte("successor content"), 0o644); err != nil {
		t.Fatal(err)
	}
	runRar(t, rar, dir, "-s", "-m3", "-md1m", "far.rar", "a_far.bin", "b_after.bin")

	f, err := os.Open(filepath.Join(dir, "far.rar"))
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan io.ReadCloser, 1)
	ch <- f
	close(ch)
	r := NewReader(ch)
	t.Cleanup(func() { _ = r.Close() })
	// The window would grow to the declared 1 MiB and decode this; the cap is
	// what keeps it at the minimum so the capacity path is exercised.
	r.SetMaxWindow(0x40000)

	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if e.Header.DictSize != 1<<20 {
		t.Fatalf("DictSize = %d, want 1 MiB", e.Header.DictSize)
	}
	if e.Header.Method == 0 {
		t.Fatalf("fixture is not a compressed member: %+v", e.Header)
	}
	n, err := io.Copy(io.Discard, e)
	if !errors.Is(err, ErrDictionaryTooLarge) || !errors.Is(err, ErrWindowOffsetBounds) {
		t.Fatalf("Read verdict = %v, want ErrDictionaryTooLarge wrapping ErrWindowOffsetBounds", err)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("verdict %v satisfies io.EOF", err)
	}
	if n >= int64(2*half) || n == 0 {
		t.Fatalf("delivered %d bytes of %d, want a partial delivery", n, 2*half)
	}
	if got := e.Close(); !errors.Is(got, ErrDictionaryTooLarge) {
		t.Fatalf("Close verdict = %v, want the same ErrDictionaryTooLarge", got)
	}
	if !e.short() {
		t.Fatal("member that hit the capacity limit is not short")
	}

	// The window is marked damaged: the solid successor is refused.
	next, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after the failed member: %v", err)
	}
	_, err = io.Copy(io.Discard, next)
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor verdict = %v, want ErrSolidStreamBroken", err)
	}
}

// A far reference whose header declares a dictionary that fits the window is
// corruption by definition: the stream outran its own header. Same archive
// shape as above with the declared size patched down is not expressible with
// rar (it sizes the dictionary to what it used), so this shows the converse
// on the real decoder with a declared size equal to the window.
func TestFarReferenceWithSmallDeclaredDictionaryIsCorruption(t *testing.T) {
	rar := rarOrSkip(t)
	dir := t.TempDir()
	const half = 300000
	randomThenRepeat(t, filepath.Join(dir, "a_far.bin"), half)
	runRar(t, rar, dir, "-m3", "-md1m", "far.rar", "a_far.bin")

	f, err := os.Open(filepath.Join(dir, "far.rar"))
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan io.ReadCloser, 1)
	ch <- f
	close(ch)
	r := NewReader(ch)
	t.Cleanup(func() { _ = r.Close() })
	r.SetMaxWindow(0x40000)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the header declared exactly what the window holds.
	r.dec50.dictSize = int64(r.win.size)
	_, err = io.Copy(io.Discard, e)
	if !errors.Is(err, ErrWindowOffsetBounds) || errors.Is(err, ErrDictionaryTooLarge) {
		t.Fatalf("verdict = %v, want ErrWindowOffsetBounds alone", err)
	}
}

// With a window above 32 MiB, one fill stages the 16 MiB target rather than
// half the window. 40 MiB of compressible text under -md64m: a single fill on
// the 64 MiB window the member grows must stop near 16 MiB, where the old
// size/2 rule would have staged twice that. Needs rar; skips under -short.
func TestFillStopsAtTheCapOnALargeWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ~40 MB of scratch data")
	}
	rar := rarOrSkip(t)
	dir := t.TempDir()
	// Deterministic pseudo-text: compressible, yet with enough variety that a
	// fill produces real output rather than one long match.
	words := []string{"alpha ", "bravo ", "charlie ", "delta ", "echo ", "foxtrot ", "golf ", "hotel ", "india ", "juliet "}
	var sb strings.Builder
	x := uint64(2463534242)
	for sb.Len() < 40<<20 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		sb.WriteString(words[x%uint64(len(words))])
	}
	if err := os.WriteFile(filepath.Join(dir, "text.txt"), []byte(sb.String()), 0o644); err != nil {
		t.Skipf("cannot write scratch file: %v", err)
	}
	runRar(t, rar, dir, "-m3", "-md64m", "text.rar", "text.txt")

	f, err := os.Open(filepath.Join(dir, "text.rar"))
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan io.ReadCloser, 1)
	ch <- f
	close(ch)
	r := NewReader(ch)
	t.Cleanup(func() { _ = r.Close() })
	r.SetMaxWindow(64 << 20) // above the non-Linux default cap
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if e.Header.Method == 0 {
		t.Fatal("rar stored the text; the fixture needs a compressed member")
	}
	if r.win.size != 64<<20 {
		t.Fatalf("window = %d, want 64 MiB", r.win.size)
	}
	if err := r.dec50.fill(r.win); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("fill: %v", err)
	}
	staged := r.win.Available()
	target := r.win.fillTarget()
	if target != maxFillTarget {
		t.Fatalf("fillTarget = %d, want the %d cap", target, maxFillTarget)
	}
	// One more symbol at most past the target; far below the 32 MiB that
	// size/2 would have staged.
	if staged < target || staged > target+4097 {
		t.Fatalf("one fill staged %d bytes, want between %d and %d", staged, target, target+4097)
	}
}

// The issue's archives at full size: 80 MB of data whose second half repeats
// the first, packed with -md32m (both halves literal) and -md64m (second half
// a 40 MB match). Both decode now that the window follows the declaration;
// the -md64m archive is then read again under a 32 MiB cap, which is the
// configuration this library shipped with and the one that still reports the
// capacity limit.
func TestIssue79FarArchivesAtFullSize(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ~170 MB of scratch data")
	}
	rar := rarOrSkip(t)
	dir := t.TempDir()
	const half = 40 << 20
	randomThenRepeat(t, filepath.Join(dir, "a_far.bin"), half)
	want, err := os.ReadFile(filepath.Join(dir, "a_far.bin"))
	if err != nil {
		t.Skipf("cannot read scratch file back: %v", err)
	}
	runRar(t, rar, dir, "-m3", "-md32m", "far_32m.rar", "a_far.bin")
	runRar(t, rar, dir, "-m3", "-md64m", "far_64m.rar", "a_far.bin")

	open := func(name string) *Reader {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan io.ReadCloser, 1)
		ch <- f
		close(ch)
		r := NewReader(ch)
		t.Cleanup(func() { _ = r.Close() })
		r.SetMaxWindow(64 << 20) // above the non-Linux default cap
		return r
	}
	decodes := func(name string, dict int64) {
		r := open(name)
		e, err := r.NextEntry()
		if err != nil {
			t.Fatal(err)
		}
		if e.Header.DictSize != dict {
			t.Fatalf("%s DictSize = %d, want %d", name, e.Header.DictSize, dict)
		}
		var got bytes.Buffer
		got.Grow(len(want))
		if _, err := io.Copy(&got, e); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("%s content differs", name)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("%s Close: %v", name, err)
		}
		// rar stores the -md32m member (nothing within 32 MiB matches, and
		// the halves are incompressible), and a stored member of a non-solid
		// archive leaves the window alone. The -md64m member is compressed.
		switch {
		case e.Header.Method == 0 && r.win.size != minWindowSize:
			t.Fatalf("%s is stored but grew the window to %d", name, r.win.size)
		case e.Header.Method != 0 && r.win.size != int(dict):
			t.Fatalf("%s left the window at %d, want %d", name, r.win.size, dict)
		}
	}

	decodes("far_32m.rar", 32<<20)
	decodes("far_64m.rar", 64<<20)

	// Capped at the old fixed size, the -md64m archive ends short exactly as
	// it did before the window could grow.
	r := open("far_64m.rar")
	r.SetMaxWindow(32 << 20)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if r.win.size != 32<<20 {
		t.Fatalf("capped window = %d, want 32 MiB", r.win.size)
	}
	n, err := io.Copy(io.Discard, e)
	if !errors.Is(err, ErrDictionaryTooLarge) || !errors.Is(err, ErrWindowOffsetBounds) || errors.Is(err, io.EOF) {
		t.Fatalf("far_64m verdict = %v", err)
	}
	// Records current behaviour, not a promise: Read reports a decode failure
	// before serving the output that decode step had already produced, so this
	// is less than the 40 MiB at which the first far match sits. Documented on
	// ErrDictionaryTooLarge.
	if n != 33554432 {
		t.Fatalf("far_64m delivered %d bytes, want 33554432", n)
	}
	if got := e.Close(); !errors.Is(got, ErrDictionaryTooLarge) {
		t.Fatalf("far_64m Close = %v, want ErrDictionaryTooLarge", got)
	}
}
