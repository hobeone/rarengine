package rarengine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeArchive puts a hand-built archive on disk under a name that volume
// discovery treats as a single self-contained volume.
func writeArchive(t *testing.T, blocks ...[]byte) string {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(rar5ArchiveHeader())
	for _, b := range blocks {
		buf.Write(b)
	}
	buf.Write(rar5EndHeader())

	path := filepath.Join(t.TempDir(), "damaged.rar")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return path
}

func onlyDamaged(t *testing.T, res UnpackResult) DamagedEntry {
	t.Helper()

	if len(res.Damaged) != 1 {
		t.Fatalf("expected exactly 1 damaged entry, got %d: %+v", len(res.Damaged), res.Damaged)
	}
	if res.Damaged[0].Header == nil {
		t.Fatal("damaged entry has a nil Header; the caller cannot say which member was lost")
	}
	return res.Damaged[0]
}

// TestUnpackDir_TruncatedMemberDoesNotStopExtraction is the acceptance test
// for the gap #30 left behind.
//
// The engine learned to continue past a damaged member, but UnpackDir -- the
// one high-level consumer, and the entry point the README recommends -- still
// aborted and returned nil, so the feature was unreachable from the API most
// callers use.
func TestUnpackDir_TruncatedMemberDoesNotStopExtraction(t *testing.T) {
	intact := []byte("this member is entirely readable")
	archive := writeArchive(t, shortEntry("truncated.bin"), goodEntry("intact.bin", intact))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("UnpackDir returned a fatal error for a single damaged member: %v", err)
	}

	if len(res.Files) != 1 {
		t.Fatalf("expected the intact member to be extracted, got %v", res.Files)
	}
	if filepath.Base(res.Files[0]) != "intact.bin" {
		t.Errorf("extracted %q; want intact.bin", res.Files[0])
	}
	got, err := os.ReadFile(res.Files[0])
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if !bytes.Equal(got, intact) {
		t.Errorf("extracted content %q; want %q", got, intact)
	}

	d := onlyDamaged(t, res)
	if d.Header.Name != "truncated.bin" {
		t.Errorf("damaged entry names %q; want truncated.bin", d.Header.Name)
	}
	if !errors.Is(d.Err, ErrTruncatedFile) {
		t.Errorf("damaged entry carries %v; want ErrTruncatedFile", d.Err)
	}
}

// TestUnpackDir_DamagedMemberLeavesNothingOnDisk pins the removal of the
// partial file.
//
// extractEntry creates the output file and writes into it before the read
// fails, and reports no path for it. Left behind, a truncated file sits in the
// output directory looking exactly like a complete one, and no field of
// UnpackResult mentions it -- the same present-wrong-bytes-as-good failure the
// checksum work exists to prevent.
func TestUnpackDir_DamagedMemberLeavesNothingOnDisk(t *testing.T) {
	archive := writeArchive(t, shortEntry("truncated.bin"), goodEntry("intact.bin", []byte("ok")))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}
	onlyDamaged(t, res)

	if _, err := os.Stat(filepath.Join(out, "truncated.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the damaged member was left on disk (stat err %v); a partial file is "+
			"indistinguishable from a complete one once extraction has finished", err)
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("output directory holds %d entries; want only the intact member", len(entries))
	}
}

// TestUnpackDir_ChecksumFailureIsRecorded covers the case that made the read
// site load-bearing.
//
// A member that reaches its declared size and then fails its CRC32 surfaces
// the mismatch during the read, and the following Next returns the NEXT
// header cleanly rather than a FileError. Recording damage only from
// FileError therefore dropped this member from Files and Damaged alike, and
// reported the archive as fully extracted.
func TestUnpackDir_ChecksumFailureIsRecorded(t *testing.T) {
	archive := writeArchive(t,
		badCRCEntry("wrong.bin", []byte("content whose checksum will not match")),
		goodEntry("intact.bin", []byte("ok")),
	)
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}

	d := onlyDamaged(t, res)
	if d.Header.Name != "wrong.bin" {
		t.Errorf("damaged entry names %q; want wrong.bin", d.Header.Name)
	}
	if !errors.Is(d.Err, ErrCRCMismatch) {
		t.Errorf("damaged entry carries %v; want ErrCRCMismatch", d.Err)
	}
	if len(res.Files) != 1 || filepath.Base(res.Files[0]) != "intact.bin" {
		t.Errorf("expected only intact.bin extracted, got %v", res.Files)
	}
	if _, err := os.Stat(filepath.Join(out, "wrong.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the CRC-failed member was left on disk (stat err %v)", err)
	}
}

// TestUnpackDir_DamageIsRecordedOnce pins the deduplication.
//
// A truncated member is seen twice: once as the bare cause from the read, and
// again as the FileError Next builds for the same file. Both sites have to
// record -- neither alone covers every shape -- so without the suppression one
// lost member is reported as two, and a caller counting Damaged overstates the
// loss.
func TestUnpackDir_DamageIsRecordedOnce(t *testing.T) {
	archive := writeArchive(t,
		shortEntry("truncated.bin"),
		goodEntry("intact.bin", []byte("ok")),
		badCRCEntry("wrong.bin", []byte("also damaged, differently")),
	)
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}

	if len(res.Damaged) != 2 {
		t.Fatalf("expected 2 damaged members, got %d: %+v", len(res.Damaged), res.Damaged)
	}
	names := []string{res.Damaged[0].Header.Name, res.Damaged[1].Header.Name}
	if names[0] != "truncated.bin" || names[1] != "wrong.bin" {
		t.Errorf("damaged members are %v; want [truncated.bin wrong.bin] in archive order", names)
	}
	if len(res.Files) != 1 {
		t.Errorf("expected 1 extracted file, got %v", res.Files)
	}
}

// TestUnpackDir_CleanArchiveReportsNoDamage is the negative control for the
// whole mechanism: nothing above proves the reporting is driven by real damage
// unless an undamaged archive reports none.
func TestUnpackDir_CleanArchiveReportsNoDamage(t *testing.T) {
	archive := writeArchive(t, goodEntry("a.bin", []byte("first")), goodEntry("b.bin", []byte("second")))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}
	if len(res.Damaged) != 0 {
		t.Errorf("clean archive reported damage: %+v", res.Damaged)
	}
	if len(res.Files) != 2 {
		t.Errorf("expected 2 extracted files, got %v", res.Files)
	}
}

// TestUnpackDir_SolidArchiveStopsButKeepsWhatItGot pins the documented
// exception, and the reason every exit returns the result.
//
// Solid members back-reference their predecessors' decoded bytes, so once one
// member is damaged the rest cannot be reconstructed and the engine refuses
// them with ErrSolidStreamBroken -- which is not a FileError and correctly
// ends the traversal. What must not follow is the old behaviour of discarding
// everything: the members extracted before the damage are on disk, and
// returning nil alongside the error hid them from the caller.
func TestUnpackDir_SolidArchiveStopsButKeepsWhatItGot(t *testing.T) {
	first := []byte("this member extracts cleanly")
	archive := writeArchive(t,
		goodEntry("first.bin", first),
		shortEntry("truncated.bin"),
		rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234, []byte("depends on history")),
	)
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("UnpackDir returned %v; want ErrSolidStreamBroken", err)
	}

	if len(res.Files) != 1 || filepath.Base(res.Files[0]) != "first.bin" {
		t.Errorf("the clean member extracted before the damage was lost: %v", res.Files)
	}
	d := onlyDamaged(t, res)
	if d.Header.Name != "truncated.bin" {
		t.Errorf("damaged entry names %q; want truncated.bin", d.Header.Name)
	}
}
