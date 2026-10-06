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
		r := NewReader(fileVolumesOf(t, file))
		if configure != nil {
			configure(r)
		}
		for i := 0; ; i++ {
			e, err := r.NextEntry()
			if errors.Is(err, io.EOF) {
				break
			}
			o := decodeOutcome{file: filepath.Base(file), index: i}
			if err != nil {
				o.err = err.Error()
				out = append(out, o)
				break
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
		_ = r.Close()
	}
	return out
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
	got := decodeAll(t, goldenFixtures(t), nil)
	path := filepath.Join("testdata", "decode_golden.tsv")
	if os.Getenv("RARENGINE_WRITE_GOLDEN") == "1" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriter(f)
		for _, o := range got {
			_, _ = fmt.Fprintln(w, o.line()) // a write error surfaces at Flush
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		t.Skip("golden rewritten")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	var want []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want = append(want, sc.Text())
	}
	if len(want) != len(got) {
		t.Fatalf("golden has %d outcomes, decoder produced %d", len(want), len(got))
	}
	for i := range got {
		if got[i].line() != want[i] {
			t.Errorf("outcome %d differs\n got: %s\nwant: %s", i, got[i].line(), want[i])
		}
	}
}
