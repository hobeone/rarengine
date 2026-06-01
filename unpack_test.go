package rarengine

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSortVolumes(t *testing.T) {
	// Scramble standard volume paths order
	input := []string{
		filepath.Join("testdata", "rar5_multi.part03.rar"),
		filepath.Join("testdata", "rar5_multi.part01.rar"),
		filepath.Join("testdata", "rar5_multi.part02.rar"),
	}

	expected := []string{
		filepath.Join("testdata", "rar5_multi.part01.rar"),
		filepath.Join("testdata", "rar5_multi.part02.rar"),
		filepath.Join("testdata", "rar5_multi.part03.rar"),
	}

	sorted, err := SortVolumes(input)
	if err != nil {
		t.Fatalf("SortVolumes failed: %v", err)
	}

	if !reflect.DeepEqual(sorted, expected) {
		t.Errorf("SortVolumes output mismatch:\nexpected: %v\ngot:      %v", expected, sorted)
	}
}

func TestUnpackDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rarengine_unpack_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a text handler that logs to a buffer so we can verify structured log statements
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	firstVolume := filepath.Join("testdata", "rar5_multi.part01.rar")
	opts := UnpackOptions{
		Logger: logger,
	}

	_, err = UnpackDir(context.Background(), firstVolume, tmpDir, opts)
	if err != nil {
		t.Fatalf("UnpackDir failed: %v", err)
	}

	// Verify log outputs
	logStr := logBuf.String()
	requiredLogs := []string{
		"rarengine: starting volume discovery",
		"rarengine: discovered volumes",
		"rarengine: sorting volumes by internal headers",
		"rarengine: sorted volumes order",
		"rarengine: starting extraction pipeline",
		"rarengine: extracting entry",
		"rarengine: extracted entry complete",
		"rarengine: extraction pipeline complete",
	}

	for _, req := range requiredLogs {
		if !bytes.Contains(logBuf.Bytes(), []byte(req)) {
			t.Errorf("expected log statement %q not found in log output:\n%s", req, logStr)
		}
	}

	// Verify extracted files exist and are correct
	// rar5_multi contains "large.bin" (8192 bytes)
	largeBinPath := filepath.Join(tmpDir, "large.bin")
	stat, err := os.Stat(largeBinPath)
	if err != nil {
		t.Fatalf("large.bin was not extracted: %v", err)
	}
	if stat.Size() != 8192 {
		t.Errorf("expected large.bin to be 8192 bytes, got %d", stat.Size())
	}
}

func TestUnpackDir_Options(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rarengine_options_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	firstVolume := filepath.Join("testdata", "rar5_multi.part01.rar")

	// 1. Test basic extraction with returned paths
	var entries []string
	opts := UnpackOptions{
		OneFolder: true,
		OnEntry: func(h *FileHeader) {
			entries = append(entries, h.Name)
		},
	}

	files, err := UnpackDir(context.Background(), firstVolume, tmpDir, opts)
	if err != nil {
		t.Fatalf("UnpackDir failed: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 extracted file path, got %d: %v", len(files), files)
	}

	// rar5_multi contains "large.bin"
	if len(entries) != 1 || entries[0] != "large.bin" {
		t.Errorf("OnEntry callback failed or had incorrect entries: %v", entries)
	}

	// Verify the file was flattened to the root of tmpDir
	flatFile := filepath.Join(tmpDir, "large.bin")
	if _, err := os.Stat(flatFile); err != nil {
		t.Errorf("expected flat large.bin to exist at %s: %v", flatFile, err)
	}

	// 2. Test OneFolder duplicate collision (OverwriteFiles = false)
	optsCollision := UnpackOptions{
		OneFolder:      true,
		OverwriteFiles: false,
	}
	filesCollision, err := UnpackDir(context.Background(), firstVolume, tmpDir, optsCollision)
	if err != nil {
		t.Fatalf("UnpackDir with collision failed: %v", err)
	}
	if len(filesCollision) != 1 {
		t.Fatalf("expected 1 collision-extracted file path, got %v", filesCollision)
	}
	collisionFile := filepath.Join(tmpDir, "large_1.bin")
	if _, err := os.Stat(collisionFile); err != nil {
		t.Errorf("expected unique path file %s to exist: %v", collisionFile, err)
	}
}

func TestSortVolumes_ResilientFallback(t *testing.T) {
	input := []string{
		"rar5_multi.part03.rar",
		"rar5_multi.part01.rar",
		"rar5_multi.part02.rar",
	}

	expected := []string{
		"rar5_multi.part01.rar",
		"rar5_multi.part02.rar",
		"rar5_multi.part03.rar",
	}

	sorted, err := SortVolumes(input)
	if err != nil {
		t.Fatalf("SortVolumes failed: %v", err)
	}

	if !reflect.DeepEqual(sorted, expected) {
		t.Errorf("expected %v, got %v", expected, sorted)
	}
}

func TestUnpackDir_CancelMidCopy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rarengine_cancel_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	firstVolume := filepath.Join("testdata", "rar5_multi.part01.rar")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately

	_, err = UnpackDir(ctx, firstVolume, tmpDir, UnpackOptions{})
	if err == nil {
		t.Fatal("expected UnpackDir to fail with context error, but it succeeded")
	}
	if !reflect.DeepEqual(err, context.Canceled) && !bytes.Contains([]byte(err.Error()), []byte("context canceled")) {
		t.Errorf("expected context canceled error, got: %v", err)
	}
}

func TestDiscoverVolumes_ClassicScheme(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rarengine_classic_discover")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	files := []string{
		filepath.Join(tmpDir, "archive.rar"),
		filepath.Join(tmpDir, "archive.r00"),
		filepath.Join(tmpDir, "archive.r01"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("dummy"), 0644); err != nil {
			t.Fatalf("failed to write dummy file %s: %v", f, err)
		}
	}

	// 1. Call with archive.rar
	vols, err := discoverVolumes(filepath.Join(tmpDir, "archive.rar"))
	if err != nil {
		t.Fatalf("discoverVolumes failed: %v", err)
	}
	if len(vols) != 3 {
		t.Errorf("expected 3 volumes, got %d: %v", len(vols), vols)
	}

	// 2. Call with archive.r00
	vols00, err := discoverVolumes(filepath.Join(tmpDir, "archive.r00"))
	if err != nil {
		t.Fatalf("discoverVolumes failed: %v", err)
	}
	if len(vols00) != 3 {
		t.Errorf("expected 3 volumes when called with r00, got %d: %v", len(vols00), vols00)
	}
}

func TestSetupSandbox_Error(t *testing.T) {
	// Create a temp file so that MkdirAll fails on it
	tmpFile, err := os.CreateTemp("", "rarengine_sandbox_err")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// MkdirAll should fail because tmpFile.Name() already exists as a non-directory file
	_, _, err = setupSandbox(tmpFile.Name())
	if err == nil {
		t.Errorf("expected setupSandbox to return an error, got nil")
	}
}

func TestOpenVolumeChannel_Error(t *testing.T) {
	// Create one valid temp file
	tmpFile, err := os.CreateTemp("", "rarengine_open_vol_err")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Sequence contains one valid file and one non-existent file
	vols := []string{tmpFile.Name(), "nonexistent_volume_path.rar"}
	_, err = openVolumeChannel(vols)
	if err == nil {
		t.Errorf("expected openVolumeChannel to return an error, got nil")
	}
}
