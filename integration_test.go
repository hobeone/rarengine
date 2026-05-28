package rarengine_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

func TestIntegration_Encrypted(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rar5_encrypted.rar"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	sd := rarengine.NewStreamDecompressor(volumes)
	sd.SetPassword("test")

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Name != "hello.txt" {
		t.Errorf("expected file 'hello.txt', got '%s'", fh.Name)
	}

	data := make([]byte, fh.UnpackedSize)
	_, err = io.ReadFull(sd, data)
	if err != nil {
		t.Fatalf("failed to read content of %s: %v", fh.Name, err)
	}

	expectedContent := "hello rardecode"
	if string(data) != expectedContent {
		t.Errorf("content mismatch: expected %q, got %q", expectedContent, string(data))
	}
}

func TestIntegration_Oracle(t *testing.T) {
	// Verify unrar is available on system
	unrarPath, err := exec.LookPath("unrar")
	if err != nil {
		t.Skip("unrar binary not found on path, skipping oracle test")
	}

	testArchives := []struct {
		filename string
		password string
	}{
		{"rar5_store.rar", ""},
		{"rar5_compress.rar", ""},
		{"rar5_solid.rar", ""},
		{"rar5_encrypted.rar", "test"},
	}

	for _, tc := range testArchives {
		t.Run(tc.filename, func(t *testing.T) {
			archivePath := filepath.Join("testdata", tc.filename)
			tempDir := t.TempDir()

			// Extract using oracle unrar
			passwordArg := "-p-"
			if tc.password != "" {
				passwordArg = "-p" + tc.password
			}

			// We append / to the end of target directory for unrar destination
			cmd := exec.Command(unrarPath, "x", "-y", passwordArg, archivePath, tempDir+string(filepath.Separator))
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("unrar command failed: %v, stderr: %s", err, stderr.String())
			}

			// Open archive using StreamDecompressor
			f, err := os.Open(archivePath)
			if err != nil {
				t.Fatalf("failed to open archive: %v", err)
			}
			defer f.Close()

			volumes := make(chan io.ReadCloser, 1)
			volumes <- f
			close(volumes)

			sd := rarengine.NewStreamDecompressor(volumes)
			if tc.password != "" {
				sd.SetPassword(tc.password)
			}

			// Track files extracted by decompressor to match with oracle directory
			extractedFiles := make(map[string]bool)

			for {
				fh, err := sd.Next()
				if err != nil {
					if errors.Is(err, rarengine.ErrNoNextVolume) || err == io.EOF {
						break
					}
					t.Fatalf("Next() failed: %v", err)
				}

				if fh.IsDir {
					continue
				}

				extractedFiles[fh.Name] = true

				// Read oracle file content
				oracleFilePath := filepath.Join(tempDir, fh.Name)
				oracleData, err := os.ReadFile(oracleFilePath)
				if err != nil {
					t.Fatalf("failed to read oracle file %q: %v", fh.Name, err)
				}

				// Decompress content using rarengine
				data := make([]byte, fh.UnpackedSize)
				_, err = io.ReadFull(sd, data)
				if err != nil {
					t.Fatalf("failed to read content of %s: %v", fh.Name, err)
				}

				if !bytes.Equal(data, oracleData) {
					t.Errorf("content mismatch for file %q: expected size %d, got size %d", fh.Name, len(oracleData), len(data))
				}
			}

			// Verify all non-empty files in the oracle directory were matched by the decompressor
			err = filepath.WalkDir(tempDir, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				relPath, err := filepath.Rel(tempDir, path)
				if err != nil {
					return err
				}
				if !extractedFiles[relPath] {
					t.Errorf("file %q extracted by oracle but not by decompressor", relPath)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("failed to walk oracle directory: %v", err)
			}
		})
	}
}
