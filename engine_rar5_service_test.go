package rarengine_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hobeone/rarengine"
)

// decodeAll drains every entry an archive yields, returning the names in order
// and their concatenated contents.
func decodeAll(ch <-chan io.ReadCloser) ([]string, []byte, error) {
	sd := rarengine.NewStreamDecompressor(ch)

	var names []string
	var content []byte
	for {
		fh, err := sd.Next()
		if err != nil {
			if errors.Is(err, rarengine.ErrNoNextVolume) || errors.Is(err, io.EOF) {
				return names, content, nil
			}
			return names, content, err
		}
		names = append(names, fh.Name)
		data, err := io.ReadAll(sd)
		if err != nil {
			return names, content, fmt.Errorf("reading %s: %w", fh.Name, err)
		}
		content = append(content, data...)
	}
}

// fixtureVolumes opens the named fixtures and returns them as a volume channel.
func fixtureVolumes(t *testing.T, names ...string) <-chan io.ReadCloser {
	t.Helper()

	ch := make(chan io.ReadCloser, len(names))
	for _, name := range names {
		f, err := os.Open(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("opening %s: %v", name, err)
		}
		t.Cleanup(func() { _ = f.Close() })
		ch <- f
	}
	close(ch)
	return ch
}

// TestServiceHeadersNotSurfaced covers service records being skipped rather
// than yielded as files. Service headers reuse the file-header layout, so
// without the type check Next() reports the quick open record as a file named
// "QO" and hands its bytes to the caller as file contents.
//
// rar5_exe_filter.rar is the only fixture large enough for rar to add one.
func TestServiceHeadersNotSurfaced(t *testing.T) {
	names, _, err := decodeAll(fixtureVolumes(t, "rar5_exe_filter.rar"))
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(names) != 1 || names[0] != "own.exe" {
		t.Fatalf("archive yielded %v, want [own.exe]", names)
	}
}

// TestMultiVolumeServiceRecords covers the same skip across a split archive,
// where every volume carries a quick open and a recovery record after its file
// block. It also exercises the filter queue spanning volume boundaries, since
// the payload is the same compiled x86 content.
func TestMultiVolumeServiceRecords(t *testing.T) {
	_, single, err := decodeAll(fixtureVolumes(t, "rar5_exe_filter.rar"))
	if err != nil {
		t.Fatalf("decoding the single-volume fixture: %v", err)
	}

	names, split, err := decodeAll(fixtureVolumes(t,
		"rar5_multi_service.part01.rar",
		"rar5_multi_service.part02.rar",
		"rar5_multi_service.part03.rar",
		"rar5_multi_service.part04.rar",
	))
	if err != nil {
		t.Fatalf("decoding the split archive: %v", err)
	}

	if len(names) != 1 || names[0] != "own.exe" {
		t.Fatalf("archive yielded %v, want [own.exe]", names)
	}
	if !bytes.Equal(split, single) {
		t.Errorf("split archive decoded %d bytes, single-volume decoded %d; contents differ",
			len(split), len(single))
	}
}
