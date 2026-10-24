package rarengine

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// FuzzRAR4Header holds the RAR4 header parsers to the contract the traversal
// relies on, for any bytes: no panic, and a header parsed without error has
// PackedSize equal to the non-negative count the traversal skips by, a name
// that is valid UTF-8 and already sanitized, a method 0-5, and no dictionary
// size.
func FuzzRAR4Header(f *testing.F) {
	files, err := filepath.Glob("testdata/rar4_*.r*")
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		arc, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		r := bytes.NewReader(arc[len(rar4Sig):])
		for {
			start := len(arc) - r.Len()
			h, err := readBlockHeader4(r)
			if err != nil {
				break
			}
			f.Add(arc[start : len(arc)-r.Len()])
			if _, err := r.Seek(h.DataSize, io.SeekCurrent); err != nil {
				break
			}
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := readBlockHeader4(bytes.NewReader(data))
		if err != nil || (h.Type != headerTypeFile && h.Type != headerTypeService) {
			return
		}
		fh, err := parseFileHeader4(h)
		if err != nil || fh == nil {
			return
		}
		if fh.PackedSize != h.DataSize || h.DataSize < 0 {
			t.Errorf("PackedSize %d, DataSize %d", fh.PackedSize, h.DataSize)
		}
		if !utf8.ValidString(fh.Name) || fh.Name != sanitizePath(fh.Name) {
			t.Errorf("name %q is not valid, sanitized UTF-8", fh.Name)
		}
		if fh.Method < 0 || fh.Method > 5 || fh.DictSize != 0 {
			t.Errorf("Method %d DictSize %d", fh.Method, fh.DictSize)
		}
	})
}
