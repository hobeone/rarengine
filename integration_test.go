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

	r := rarengine.NewReader(volumes)

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	if e.Header.Name != "hello.txt" {
		t.Errorf("expected 'hello.txt', got '%s'", e.Header.Name)
	}

	data := make([]byte, e.Header.UnpackedSize)
	_, err = io.ReadFull(e, data)
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

	r := rarengine.NewReader(volumes)

	// Read all files
	fileCount := 0
	for {
		e, err := r.NextEntry()
		if err != nil {
			if errors.Is(err, rarengine.ErrNoNextVolume) || err == io.EOF {
				break
			}
			t.Fatalf("NextEntry() failed: %v", err)
		}

		fileCount++
		fh := e.Header
		t.Logf("Read file: Name=%q Size=%d Packed=%d Method=%d First=%v Last=%v", fh.Name, fh.UnpackedSize, fh.PackedSize, fh.Method, fh.FirstBlock, fh.LastBlock)
		// Discard/drain data
		buf := make([]byte, 4096)
		totalRead := 0
		for {
			n, err := e.Read(buf)
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
	t.Cleanup(func() { _ = f.Close() })

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	r := rarengine.NewReader(volumes)

	expected := map[string]string{
		"hello.txt":  "hello rardecode",
		"second.txt": "second file for testing",
	}

	for i := range 2 {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("[%d] NextEntry() failed: %v", i, err)
		}

		expContent, ok := expected[e.Header.Name]
		if !ok {
			t.Fatalf("unexpected file inside archive: %s", e.Header.Name)
		}

		data := make([]byte, e.Header.UnpackedSize)
		_, err = io.ReadFull(e, data)
		if err != nil {
			t.Fatalf("failed to read content of %s: %v", e.Header.Name, err)
		}

		if string(data) != expContent {
			t.Errorf("content mismatch for %s: expected %q, got %q", e.Header.Name, expContent, string(data))
		}
	}
}

func TestIntegration_Solid(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rar5_solid.rar"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	r := rarengine.NewReader(volumes)

	expected := map[string]string{
		"hello.txt":  "hello rardecode",
		"second.txt": "second file for testing",
	}

	for i := range 2 {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("[%d] NextEntry() failed: %v", i, err)
		}

		expContent, ok := expected[e.Header.Name]
		if !ok {
			t.Fatalf("unexpected file inside archive: %s", e.Header.Name)
		}

		data := make([]byte, e.Header.UnpackedSize)
		_, err = io.ReadFull(e, data)
		if err != nil {
			t.Fatalf("failed to read content of %s: %v", e.Header.Name, err)
		}

		if string(data) != expContent {
			t.Errorf("content mismatch for %s: expected %q, got %q", e.Header.Name, expContent, string(data))
		}
	}
}

func TestIntegration_Encrypted(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rar5_encrypted.rar"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	r := rarengine.NewReader(volumes)
	r.SetPasswords([]string{"test"})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	if e.Header.Name != "hello.txt" {
		t.Errorf("expected file 'hello.txt', got '%s'", e.Header.Name)
	}

	data := make([]byte, e.Header.UnpackedSize)
	_, err = io.ReadFull(e, data)
	if err != nil {
		t.Fatalf("failed to read content of %s: %v", e.Header.Name, err)
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

	// volumes lists every part in order; the first is what unrar is handed,
	// and it finds the rest itself. Multi-volume archives are included
	// because the whole-file CRC lives in the LAST part's header, so they are
	// the shape most likely to produce a spurious verification failure.
	testArchives := []struct {
		name     string
		volumes  []string
		password string
	}{
		{name: "rar5_store.rar", volumes: []string{"rar5_store.rar"}},
		{name: "rar5_compress.rar", volumes: []string{"rar5_compress.rar"}},
		{name: "rar5_solid.rar", volumes: []string{"rar5_solid.rar"}},
		{name: "rar5_encrypted.rar", volumes: []string{"rar5_encrypted.rar"}, password: "test"},
		// Compiled x86 payload; the only fixture that reaches the filter path.
		// See testdata/generate.sh for why, and what regenerating it must preserve.
		{name: "rar5_exe_filter.rar", volumes: []string{"rar5_exe_filter.rar"}},
		{name: "rar5_multi", volumes: []string{
			"rar5_multi.part01.rar", "rar5_multi.part02.rar", "rar5_multi.part03.rar",
			"rar5_multi.part04.rar", "rar5_multi.part05.rar", "rar5_multi.part06.rar",
			"rar5_multi.part07.rar", "rar5_multi.part08.rar", "rar5_multi.part09.rar",
			"rar5_multi.part10.rar",
		}},
		// rar3_testfile.rar is deliberately absent: it is PPMd-compressed,
		// which this library does not implement, so it cannot round-trip
		// against unrar. Its headers are tested in header_rar3_test.go.
		// Encrypted AND split. A file's ciphertext is one continuous CBC
		// stream that volume boundaries cut mid-block, so these are the only
		// fixtures where the decryption has to survive a volume advance.
		// Neither method is redundant: the compressed decoder reads ahead
		// across the boundary before emitting anything, while the store
		// reader emits each volume as it goes, so a broken splice produces
		// nothing in one and partial garbage in the other.
		{name: "rar5_encrypted_multi", password: "test", volumes: []string{
			"rar5_encrypted_multi.part01.rar", "rar5_encrypted_multi.part02.rar",
			"rar5_encrypted_multi.part03.rar", "rar5_encrypted_multi.part04.rar",
			"rar5_encrypted_multi.part05.rar", "rar5_encrypted_multi.part06.rar",
			"rar5_encrypted_multi.part07.rar", "rar5_encrypted_multi.part08.rar",
			"rar5_encrypted_multi.part09.rar", "rar5_encrypted_multi.part10.rar",
			"rar5_encrypted_multi.part11.rar",
		}},
		{name: "rar5_encrypted_multi_store", password: "test", volumes: []string{
			"rar5_encrypted_multi_store.part01.rar", "rar5_encrypted_multi_store.part02.rar",
			"rar5_encrypted_multi_store.part03.rar", "rar5_encrypted_multi_store.part04.rar",
			"rar5_encrypted_multi_store.part05.rar", "rar5_encrypted_multi_store.part06.rar",
			"rar5_encrypted_multi_store.part07.rar", "rar5_encrypted_multi_store.part08.rar",
			"rar5_encrypted_multi_store.part09.rar", "rar5_encrypted_multi_store.part10.rar",
			"rar5_encrypted_multi_store.part11.rar",
		}},
		{name: "rar5_solid_multi_qo", volumes: []string{
			"rar5_solid_multi_qo.part1.rar", "rar5_solid_multi_qo.part2.rar",
			"rar5_solid_multi_qo.part3.rar", "rar5_solid_multi_qo.part4.rar",
			"rar5_solid_multi_qo.part5.rar", "rar5_solid_multi_qo.part6.rar",
			"rar5_solid_multi_qo.part7.rar", "rar5_solid_multi_qo.part8.rar",
		}},
	}

	for _, tc := range testArchives {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := filepath.Join("testdata", tc.volumes[0])
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

			// Open archive using Reader
			volumes := make(chan io.ReadCloser, len(tc.volumes))
			for _, name := range tc.volumes {
				f, err := os.Open(filepath.Join("testdata", name))
				if err != nil {
					t.Fatalf("failed to open volume %s: %v", name, err)
				}
				t.Cleanup(func() { _ = f.Close() })
				volumes <- f
			}
			close(volumes)

			r := rarengine.NewReader(volumes)
			if tc.password != "" {
				r.SetPasswords([]string{tc.password})
			}

			// Track files extracted by decompressor to match with oracle directory
			extractedFiles := make(map[string]bool)

			for {
				e, err := r.NextEntry()
				if err != nil {
					if errors.Is(err, rarengine.ErrNoNextVolume) || err == io.EOF {
						break
					}
					t.Fatalf("NextEntry() failed: %v", err)
				}

				fh := e.Header
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

				// Read to completion rather than exactly UnpackedSize:
				// io.ReadAtLeast discards an error delivered alongside the
				// final bytes, so io.ReadFull cannot observe a truncation or
				// checksum verdict at all.
				//
				// Encrypted files record a key-derived digest in place of a
				// CRC32, which this library cannot compute, so verification is
				// unconditional and reports ErrChecksumUnsupported rather than
				// skipping the check. Comparing the decoded bytes against
				// unrar is still worth doing, and is what this test is for --
				// so that specific verdict is tolerated here rather than
				// dropping the fixture.
				data, err := io.ReadAll(e)
				if err != nil && !errors.Is(err, rarengine.ErrChecksumUnsupported) {
					t.Fatalf("failed to read content of %s: %v", fh.Name, err)
				}
				if int64(len(data)) != fh.UnpackedSize {
					t.Fatalf("read %d bytes of %s, header declares %d", len(data), fh.Name, fh.UnpackedSize)
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
