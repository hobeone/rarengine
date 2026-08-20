package rarengine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rarBombEntry declares an unpacked size far beyond what its payload could
// produce, tripping the guard in both engines.
func rarBombEntry(name string) []byte {
	return rar5FileEntry(name, 2<<20, 0xdeadbeef, []byte("tiny payload"))
}

// TestUnpackDir_RefusedBombIsRecordedAndTraversalContinues covers a member
// refused before it ever decodes.
//
// refuse drops the payload, so the stream is on the next block header and the
// members behind a rar bomb are reachable -- but the refusal came back as a
// bare error naming nothing, so UnpackDir aborted and the member appeared in
// neither Files nor Damaged. That contradicted this API's own claim that a
// member which cannot be delivered does not stop the extraction.
func TestUnpackDir_RefusedBombIsRecordedAndTraversalContinues(t *testing.T) {
	intact := []byte("the member behind the bomb")
	archive := writeArchive(t, rarBombEntry("bomb.bin"), goodEntry("intact.bin", intact))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("a refused member stopped the extraction: %v", err)
	}

	d := onlyDamaged(t, res)
	if d.Header.Name != "bomb.bin" {
		t.Errorf("damaged entry names %q; want bomb.bin", d.Header.Name)
	}
	if !errors.Is(d.Err, ErrRarBombDetected) {
		t.Errorf("damaged entry carries %v; want ErrRarBombDetected", d.Err)
	}
	if len(res.Files) != 1 || filepath.Base(res.Files[0]) != "intact.bin" {
		t.Fatalf("the member behind the bomb was lost: %v", res.Files)
	}
	got, err := os.ReadFile(res.Files[0])
	if err != nil || string(got) != string(intact) {
		t.Errorf("intact.bin reads %q (%v); want %q", got, err, intact)
	}
	if _, err := os.Stat(filepath.Join(out, "bomb.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused member was written to disk (stat err %v)", err)
	}
}

// TestUnpackDir_SolidRefusalStaysFatal is the counterweight to the test above.
//
// Continuation is offered only where it is true. A solid run cannot be
// resumed: its members back-reference decoded bytes the damaged predecessor
// never wrote, so ErrSolidStreamBroken keeps using refuse and ends traversal.
// Without this, widening refusals to "always continuable" would look correct.
func TestUnpackDir_SolidRefusalStaysFatal(t *testing.T) {
	archive := writeArchive(t,
		shortEntry("truncated.bin"),
		rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234, []byte("needs history")),
	)

	_, err := UnpackDir(context.Background(), archive, t.TempDir(), UnpackOptions{})
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("UnpackDir returned %v; want ErrSolidStreamBroken to remain fatal", err)
	}
	if _, ok := errors.AsType[*FileError](err); ok {
		t.Error("ErrSolidStreamBroken arrived as a FileError; that promises a continuation " +
			"this library cannot honour for a solid run")
	}
}

// TestUnpackDir_UnusableNameCostsOneMember covers a name sanitizePath empties.
//
// A member named ".." leaves destRel == "", which reached OpenFile and came
// back as an archive-level error, so one odd or attacker-chosen name discarded
// every member behind it -- the failure mode this whole feature removes.
func TestUnpackDir_UnusableNameCostsOneMember(t *testing.T) {
	archive := writeArchive(t, goodEntry("..", []byte("nowhere safe")), goodEntry("good.bin", []byte("fine")))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("an unusable member name stopped the extraction: %v", err)
	}

	d := onlyDamaged(t, res)
	if !errors.Is(d.Err, ErrUnusableName) {
		t.Errorf("damaged entry carries %v; want ErrUnusableName", d.Err)
	}
	if len(res.Files) != 1 || filepath.Base(res.Files[0]) != "good.bin" {
		t.Errorf("the member behind the unusable name was lost: %v", res.Files)
	}
}

// TestUnpackDir_FailedMemberDoesNotDestroyAnEarlierOne covers the destination
// two members can share.
//
// Writing straight to destRel meant the second member's failure removed the
// first member's output, so UnpackResult.Files named a path that no longer
// existed -- and under OverwriteFiles the O_TRUNC had already destroyed a good
// copy before the member was known to be bad. Members now land on a temporary
// name and are renamed into place only once they decode completely.
func TestUnpackDir_FailedMemberDoesNotDestroyAnEarlierOne(t *testing.T) {
	good := []byte("the good copy")
	archive := writeArchive(t, goodEntry("x.bin", good), badCRCEntry("x.bin", []byte("the bad copy")))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{OverwriteFiles: true})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}
	onlyDamaged(t, res)

	if len(res.Files) != 1 {
		t.Fatalf("expected 1 extracted file, got %v", res.Files)
	}
	got, err := os.ReadFile(res.Files[0])
	if err != nil {
		t.Fatalf("UnpackResult.Files names a path that cannot be read: %v", err)
	}
	if string(got) != string(good) {
		t.Errorf("the surviving file holds %q; want the good copy %q", got, good)
	}

	// No temporary file may outlive the extraction.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("output directory holds %d entries; want only the good copy: %v", len(entries), entries)
	}
}

// TestWriteCounter_RecordsFirstWriteError pins the distinction io.Copy erases.
//
// io.Copy reports a writer failure and a reader failure identically, and the
// two mean opposite things: a bad member costs one member, a full disk costs
// the archive. Reporting ENOSPC as archive damage told a caller its download
// was corrupt and invited a pointless re-fetch.
func TestWriteCounter_RecordsFirstWriteError(t *testing.T) {
	sentinel := errors.New("disk full")
	wc := &writeCounter{w: errWriter{err: sentinel}}

	if _, err := wc.Write([]byte("x")); !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v; want the underlying error", err)
	}
	if !errors.Is(wc.err, sentinel) {
		t.Fatalf("writeCounter recorded %v; want the underlying error", wc.err)
	}

	second := errors.New("a later, less informative error")
	wc.w = errWriter{err: second}
	if _, err := wc.Write([]byte("y")); !errors.Is(err, second) {
		t.Fatalf("Write returned %v; want the second error", err)
	}
	if !errors.Is(wc.err, sentinel) {
		t.Errorf("writeCounter now holds %v; the FIRST failure is the informative one", wc.err)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

// TestRefuseFile_ShortDropIsNotContinuable pins the proof refuseFile demands.
//
// discardPayload returning nil is NOT evidence the payload was dropped:
// io.Copy reports a source that ended early as success, so an archive that
// ends mid-payload leaves the count standing and the stream parked at an
// offset the block structure does not describe. settled() is what separates
// the two. Promising continuation there hands the next Next() an
// attacker-chosen offset to parse a block header out of -- the fabrication
// the packed-cursor rules exist to prevent.
//
// Without this, dropping the settled() check from refuseFile leaves the whole
// suite green.
func TestRefuseFile_ShortDropIsNotContinuable(t *testing.T) {
	var buf []byte
	buf = append(buf, rar5ArchiveHeader()...)
	entry := rarBombEntry("bomb.bin")
	buf = append(buf, entry...)
	buf = append(buf, goodEntry("unreachable.bin", []byte("never reached"))...)
	buf = append(buf, rar5EndHeader()...)

	// Cut the archive inside the bomb's payload, so dropping it runs out of
	// bytes. Six is fewer than the payload rarBombEntry carries, so the drop
	// is genuinely short rather than exactly satisfied.
	cut := len(buf) - len(goodEntry("unreachable.bin", []byte("never reached"))) - len(rar5EndHeader()) - 6
	truncated := buf[:cut]

	path := filepath.Join(t.TempDir(), "short.rar")
	if err := os.WriteFile(path, truncated, 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	res, err := UnpackDir(context.Background(), path, t.TempDir(), UnpackOptions{})
	if err == nil {
		t.Fatalf("a refusal whose payload could not be dropped was treated as recoverable; "+
			"result was %+v", res)
	}
	if _, ok := errors.AsType[*FileError](err); ok {
		t.Error("the refusal came back as a FileError, promising the stream is on the next " +
			"block header when the drop never completed")
	}
	if !errors.Is(err, ErrRarBombDetected) {
		t.Errorf("error is %v; want it to still name the refusal cause", err)
	}
}

// TestUnpackDir_MemberCannotCollideWithATemporaryName covers the name the
// archive gets to choose.
//
// The in-progress copy of a member used to be written to a name derived from
// its destination, and a name already taken was reclaimed by removing it. Both
// halves are the archive's to exploit: an archive holding "a.bin" and
// "a.bin.rarengine-part" had the second extracted, then destroyed when the
// first claimed that name -- while Files still listed it. That is the defect
// the temporary name exists to prevent, reintroduced through the suffix.
func TestUnpackDir_MemberCannotCollideWithATemporaryName(t *testing.T) {
	first := []byte("a member whose name looks like a temporary")
	archive := writeArchive(t,
		goodEntry("a.bin.rarengine-part", first),
		goodEntry("a.bin", []byte("an ordinary member")),
	)
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("expected both members extracted, got %v (damaged: %+v)", res.Files, res.Damaged)
	}

	for _, f := range res.Files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("UnpackResult.Files names a path that does not exist: %s (%v)", f, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(out, "a.bin.rarengine-part"))
	if err != nil {
		t.Fatalf("the member named like a temporary was removed: %v", err)
	}
	if string(got) != string(first) {
		t.Errorf("member reads %q; want %q", got, first)
	}

	// No temporary may outlive the extraction.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("output directory holds %d entries: %v", len(entries), names)
	}
}

// TestUnpackDir_NulInNameCostsOneMember covers a name sanitizePath preserves.
//
// sanitizePath drops "." and ".." components but leaves a NUL byte in place,
// and the filesystem calls reject it -- as a fatal error, so one such member
// cost every member behind it.
func TestUnpackDir_NulInNameCostsOneMember(t *testing.T) {
	archive := writeArchive(t,
		goodEntry("bad\x00name.bin", []byte("unwritable")),
		goodEntry("good.bin", []byte("fine")),
	)
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("a NUL in a member name stopped the extraction: %v", err)
	}
	d := onlyDamaged(t, res)
	if !errors.Is(d.Err, ErrUnusableName) {
		t.Errorf("damaged entry carries %v; want ErrUnusableName", d.Err)
	}
	if len(res.Files) != 1 || filepath.Base(res.Files[0]) != "good.bin" {
		t.Errorf("the member behind the unusable name was lost: %v", res.Files)
	}
}

// TestUnpackDir_UnusableNameSurvivesUniquePath covers the collision resolver
// turning an unusable name into a usable one.
//
// sanitizePath reduces a member named ".." to the empty string; with OneFolder
// filepath.Base makes that ".", and uniquePath -- seeing that the sandbox root
// itself exists -- renames it to "_1.". Validating after that step let the
// member land on disk as an ordinary file, recorded in neither list.
func TestUnpackDir_UnusableNameSurvivesUniquePath(t *testing.T) {
	archive := writeArchive(t,
		goodEntry("..", []byte("must never reach disk")),
		goodEntry("ok.bin", []byte("fine")),
	)
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out,
		UnpackOptions{OneFolder: true, OverwriteFiles: false})
	if err != nil {
		t.Fatalf("UnpackDir: %v", err)
	}

	d := onlyDamaged(t, res)
	if !errors.Is(d.Err, ErrUnusableName) {
		t.Errorf("damaged entry carries %v; want ErrUnusableName", d.Err)
	}
	if len(res.Files) != 1 || filepath.Base(res.Files[0]) != "ok.bin" {
		t.Errorf("extracted %v; want only ok.bin", res.Files)
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ok.bin" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("output directory holds %v; the unusable member reached disk", names)
	}
}

// TestUnpackDir_LongMemberNameExtracts covers a name that is legal but leaves
// no room for a suffix.
//
// A 254-byte component fits NAME_MAX on every filesystem this runs on. The
// staging name appended to it did not, so openat returned ENAMETOOLONG -- as
// an archive-level error, costing every member behind a perfectly valid name.
func TestUnpackDir_LongMemberNameExtracts(t *testing.T) {
	long := strings.Repeat("n", 250) + ".bin" // 254 bytes
	content := []byte("payload of a very long name")
	archive := writeArchive(t, goodEntry(long, content), goodEntry("after.bin", []byte("behind it")))
	out := t.TempDir()

	res, err := UnpackDir(context.Background(), archive, out, UnpackOptions{})
	if err != nil {
		t.Fatalf("a legal 254-byte member name stopped the extraction: %v", err)
	}
	if len(res.Damaged) != 0 {
		t.Errorf("damage reported for a healthy archive: %+v", res.Damaged)
	}
	if len(res.Files) != 2 {
		t.Fatalf("extracted %d members, want 2: %v", len(res.Files), res.Files)
	}

	got, err := os.ReadFile(filepath.Join(out, long))
	if err != nil {
		t.Fatalf("the long-named member is not at its full name: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q; want %q", got, content)
	}

	// The staging name is trimmed, never the destination.
	if _, err := os.Stat(filepath.Join(out, "after.bin")); err != nil {
		t.Errorf("the member behind the long name was lost: %v", err)
	}
}

// TestAsDamaged_TypedNilFileError covers the shape errors.AsType matches while
// leaving the pointer nil.
func TestAsDamaged_TypedNilFileError(t *testing.T) {
	var typed *FileError
	if _, ok := asDamaged(fmt.Errorf("wrapped: %w", typed)); ok {
		t.Error("a nil *FileError was accepted as a damaged member")
	}
	if _, ok := asDamaged(&FileError{Err: ErrCRCMismatch}); ok {
		t.Error("a FileError with no header was accepted; it cannot name the member")
	}
}
