package rarengine_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hobeone/rarengine"
)

func TestIntegration_Store(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rar5_store.rar"))
	if err != nil {
		t.Fatal(err)
	}

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	sd := rarengine.NewStreamDecompressor(volumes)

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Name != "hello.txt" {
		t.Errorf("expected 'hello.txt', got '%s'", fh.Name)
	}

	data := make([]byte, fh.UnpackedSize)
	_, err = io.ReadFull(sd, data)
	if err != nil {
		t.Fatalf("failed to read file content: %v", err)
	}

	// Uncompressed hello.txt from rar5_store.rar contains exactly: "hello from Unix\n" (16 bytes) or "hello from Unix"
	t.Logf("Decompressed hello.txt size %d: %q", len(data), string(data))
}

func TestIntegration_MultiVolume(t *testing.T) {
	volumes := make(chan io.ReadCloser, 11)

	// Queue the 10 volumes sequentially
	for i := 1; i <= 10; i++ {
		filename := fmt.Sprintf("rar5_multi.part%02d.rar", i)
		f, err := os.Open(filepath.Join("testdata", filename))
		if err != nil {
			t.Fatalf("failed to open volume %d: %v", i, err)
		}
		volumes <- f
	}
	close(volumes)

	sd := rarengine.NewStreamDecompressor(volumes)

	// Read all files
	fileCount := 0
	for {
		fh, err := sd.Next()
		if err != nil {
			if errors.Is(err, rarengine.ErrNoNextVolume) || err == io.EOF {
				break
			}
			t.Fatalf("Next() failed: %v", err)
		}

		fileCount++
		t.Logf("Read file: Name=%q Size=%d Packed=%d Method=%d First=%v Last=%v", fh.Name, fh.UnpackedSize, fh.PackedSize, fh.Method, fh.FirstBlock, fh.LastBlock)
		// Discard/drain data
		buf := make([]byte, 4096)
		totalRead := 0
		for {
			n, err := sd.Read(buf)
			totalRead += n
			if err != nil {
				if err == io.EOF {
					break
				}
				t.Fatalf("Read failed for %s: %v", fh.Name, err)
			}
		}
		t.Logf("Decompressed %s: total read %d bytes", fh.Name, totalRead)
		if int64(totalRead) != fh.UnpackedSize {
			t.Errorf("expected to read %d bytes, got %d", fh.UnpackedSize, totalRead)
		}
	}

	if fileCount != 1 {
		t.Errorf("expected 1 file in multi-volume archive, got %d", fileCount)
	}
}

func TestIntegration_Compress(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rar5_compress.rar"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	sd := rarengine.NewStreamDecompressor(volumes)

	expected := map[string]string{
		"hello.txt":  "hello rardecode",
		"second.txt": "second file for testing",
	}

	for i := 0; i < 2; i++ {
		fh, err := sd.Next()
		if err != nil {
			t.Fatalf("[%d] Next() failed: %v", i, err)
		}

		expContent, ok := expected[fh.Name]
		if !ok {
			t.Fatalf("unexpected file inside archive: %s", fh.Name)
		}

		data := make([]byte, fh.UnpackedSize)
		_, err = io.ReadFull(sd, data)
		if err != nil {
			t.Fatalf("failed to read content of %s: %v", fh.Name, err)
		}

		if string(data) != expContent {
			t.Errorf("content mismatch for %s: expected %q, got %q", fh.Name, expContent, string(data))
		}
	}
}

func TestIntegration_Solid(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rar5_solid.rar"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	sd := rarengine.NewStreamDecompressor(volumes)

	expected := map[string]string{
		"hello.txt":  "hello rardecode",
		"second.txt": "second file for testing",
	}

	for i := 0; i < 2; i++ {
		fh, err := sd.Next()
		if err != nil {
			t.Fatalf("[%d] Next() failed: %v", i, err)
		}

		expContent, ok := expected[fh.Name]
		if !ok {
			t.Fatalf("unexpected file inside archive: %s", fh.Name)
		}

		data := make([]byte, fh.UnpackedSize)
		_, err = io.ReadFull(sd, data)
		if err != nil {
			t.Fatalf("failed to read content of %s: %v", fh.Name, err)
		}

		if string(data) != expContent {
			t.Errorf("content mismatch for %s: expected %q, got %q", fh.Name, expContent, string(data))
		}
	}
}
