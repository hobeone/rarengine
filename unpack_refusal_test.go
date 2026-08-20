package rarengine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
