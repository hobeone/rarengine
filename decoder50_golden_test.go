package rarengine

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// decodeOutcome is what a caller can observe of one member: the bytes it
// got (hashed), how many, and the error that ended it.
type decodeOutcome struct {
	file, name string
	index      int
	n          int64
	sum        string
	err        string
}

func (o decodeOutcome) line() string {
	return fmt.Sprintf("%s\t%d\t%s\t%d\t%s\t%s", o.file, o.index, o.name, o.n, o.sum, o.err)
}

// decodeAll reads every member of every fixture with the given Reader
// setup and returns the outcomes in traversal order. configure runs on a
// fresh Reader before the first NextEntry.
func decodeAll(t *testing.T, files []string, configure func(*Reader)) []decodeOutcome {
	t.Helper()
	var out []decodeOutcome
	for _, file := range files {
		o, _ := decodeFile(t, file, configure)
		out = append(out, o...)
	}
	return out
}

// decodeFile is decodeAll for one fixture. It also returns the closed Reader,
// so a caller can read its pipeline counters.
func decodeFile(t *testing.T, file string, configure func(*Reader)) ([]decodeOutcome, *Reader) {
	t.Helper()
	r := NewReader(fileVolumesOf(t, file))
	if configure != nil {
		configure(r)
	}
	base := filepath.Base(file)
	out := readOutcomes(r)
	for i := range out {
		out[i].file = base
	}
	_ = r.Close()
	return out, r
}

// readOutcomes reads every member of r's archive: NextEntry until io.EOF,
// each member's bytes hashed. A NextEntry error ends the list with an
// outcome that carries it; a read error is recorded on its member.
func readOutcomes(r *Reader) []decodeOutcome {
	var out []decodeOutcome
	for i := 0; ; i++ {
		e, err := r.NextEntry()
		if errors.Is(err, io.EOF) {
			return out
		}
		o := decodeOutcome{index: i}
		if err != nil {
			o.err = err.Error()
			return append(out, o)
		}
		o.name = e.Header.Name
		h := sha256.New()
		n, rerr := io.Copy(h, e)
		o.n = n
		o.sum = hex.EncodeToString(h.Sum(nil))
		if rerr != nil {
			o.err = rerr.Error()
		}
		out = append(out, o)
	}
}

// goldenFixtures is every single-volume fixture under testdata. Multi-volume
// sets are excluded because their volume order is a property of the test
// that uses them, not of the file names.
func goldenFixtures(t *testing.T) []string {
	t.Helper()
	all, err := filepath.Glob(filepath.Join("testdata", "*.rar"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range all {
		base := filepath.Base(f)
		if strings.Contains(base, ".part") {
			continue
		}
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

// The serial decoder's outcome on every fixture, as recorded before the
// decode path was split into compute and apply. Regenerate only when a
// change is MEANT to alter a verdict, with RARENGINE_WRITE_GOLDEN=1, and
// say so in the commit.
func TestSerialDecodeMatchesGolden(t *testing.T) {
	files := goldenFixtures(t)
	path := filepath.Join("testdata", "decode_golden.tsv")
	write := os.Getenv("RARENGINE_WRITE_GOLDEN") == "1"
	var want map[string][]string // golden rows by fixture
	if !write {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close() //nolint:errcheck
		want = map[string][]string{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			name, _, _ := strings.Cut(sc.Text(), "\t")
			want[name] = append(want[name], sc.Text())
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	// got[i] is files[i]'s outcomes; each child writes only its own slot.
	got := make([][]decodeOutcome, len(files))
	t.Run("fixtures", func(t *testing.T) {
		for i, file := range files {
			base := filepath.Base(file)
			t.Run(base, func(t *testing.T) {
				t.Parallel()
				got[i], _ = decodeFile(t, file, nil)
				if write {
					return
				}
				rows := want[base]
				if len(rows) != len(got[i]) {
					t.Fatalf("golden has %d outcomes, decoder produced %d", len(rows), len(got[i]))
				}
				for j, o := range got[i] {
					if o.line() != rows[j] {
						t.Errorf("outcome %d differs\n got: %s\nwant: %s", j, o.line(), rows[j])
					}
				}
			})
		}
	})
	if write {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriter(f)
		for _, outs := range got { // fixture order, as goldenFixtures sorts it
			for _, o := range outs {
				_, _ = fmt.Fprintln(w, o.line()) // a write error surfaces at Flush
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		t.Skip("golden rewritten")
		return
	}
	// A fixture dropped from disk would otherwise leave its golden rows unchecked.
	if len(want) != len(files) {
		t.Errorf("golden covers %d fixtures, testdata has %d", len(want), len(files))
	}
}
