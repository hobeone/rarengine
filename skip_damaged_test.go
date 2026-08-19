package rarengine

import (
	"bytes"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// shortEntry declares more content than it carries, so the file ends before
// its declared size with packed bytes still in the stream -- the shape that
// used to cost the caller every file after it.
func shortEntry(name string) []byte {
	return rar5FileEntry(name, 100, 0xdeadbeef, []byte("only ten!!"))
}

func goodEntry(name string, content []byte) []byte {
	return rar5FileEntry(name, uint64(len(content)), crc32.ChecksumIEEE(content), content)
}

// TestSkipDamagedFile_TraversalContinues is the #30 acceptance test.
//
// A file that ends short leaves packed bytes unread. Those are drained on the
// terminal path, so the stream is already at a real block boundary and the
// files after it are reachable -- but before FileError the caller was handed a
// bare error indistinguishable from "the archive is over", and the only safe
// reading was to stop. For a Usenet download with one damaged segment that
// meant discarding every intact file in the archive.
func TestSkipDamagedFile_TraversalContinues(t *testing.T) {
	good := []byte("second file content, entirely intact")

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	archive.Write(goodEntry("good.bin", good))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if fh.Name != "truncated.bin" {
		t.Fatalf("first entry is %q; the fixture is not the shape this tests", fh.Name)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the damaged file returned %v; want ErrTruncatedFile", err)
	}

	// Next reports the failure rather than the following header.
	_, err = sd.Next()
	var fe *FileError
	if !errors.As(err, &fe) {
		t.Fatalf("Next after a short file returned %v (%T); want a *FileError, "+
			"which is what tells the caller traversal can continue", err, err)
	}
	if fe.Header == nil || fe.Header.Name != "truncated.bin" {
		t.Fatalf("FileError names %v; want the file that failed", fe.Header)
	}
	// The wrapper must not hide the cause: callers already switch on these.
	if !errors.Is(err, ErrTruncatedFile) {
		t.Errorf("errors.Is(err, ErrTruncatedFile) = false through FileError; "+
			"wrapping must not break the sentinels (got %v)", err)
	}

	// The point of the type: the stream was already positioned, so this works.
	fh2, err := sd.Next()
	if err != nil {
		t.Fatalf("Next after FileError returned %v; a FileError promises "+
			"traversal can continue, so this must reach the next file", err)
	}
	if fh2.Name != "good.bin" {
		t.Fatalf("continued to %q; want good.bin", fh2.Name)
	}
	got, err := io.ReadAll(sd)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading the intact file after a damaged one: %v", err)
	}
	if !bytes.Equal(got, good) {
		t.Errorf("the file after a damaged one decoded to %q; want %q. Skipping "+
			"must not disturb what follows", got, good)
	}
}

// TestSkipDamagedFile_SolidSuccessorRefused pins the case where skipping is
// NOT safe.
//
// Solid files share one LZ77 history. A damaged predecessor never writes the
// bytes its solid successor back-references, so decoding it produces
// plausible-looking output with no marker that it is wrong -- silent
// corruption, which is worse than the lost-files problem FileError solves.
func TestSkipDamagedFile_SolidSuccessorRefused(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	// FileCompSolid: this file's back-references reach into the damaged one.
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234,
		[]byte("twenty bytes exactly")))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the damaged file returned %v; want ErrTruncatedFile", err)
	}

	var fe *FileError
	if _, err := sd.Next(); !errors.As(err, &fe) {
		t.Fatalf("Next after a short file returned %v; want a *FileError", err)
	}

	_, err := sd.Next()
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("continuing into a solid file after damage returned %v; want "+
			"ErrSolidStreamBroken. Decoding it would emit bytes derived from "+
			"history that was never written", err)
	}
}

// TestSkipDamagedFile_NonSolidSuccessorClearsDamage pins the other half: a
// non-solid file resets the window, so it owes nothing to the damaged file and
// neither does the solid run that starts on top of it. Refusing here would
// make the guard above cost far more than it protects.
func TestSkipDamagedFile_NonSolidSuccessorClearsDamage(t *testing.T) {
	first := []byte("independent file, resets the window")
	second := []byte("solid on top of a clean base!!!")

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	archive.Write(goodEntry("independent.bin", first))
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, uint64(len(second)),
		crc32.ChecksumIEEE(second), second))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the damaged file: %v", err)
	}
	var fe *FileError
	if _, err := sd.Next(); !errors.As(err, &fe) {
		t.Fatalf("want *FileError, got %v", err)
	}

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("non-solid file after damage returned %v; it resets the "+
			"window and owes the damaged file nothing", err)
	}
	if fh.Name != "independent.bin" {
		t.Fatalf("reached %q; want independent.bin", fh.Name)
	}
	if _, err := io.Copy(io.Discard, sd); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading independent.bin: %v", err)
	}

	fh, err = sd.Next()
	if err != nil {
		t.Fatalf("solid file built on a clean base returned %v; the damage was "+
			"cleared by the non-solid file before it", err)
	}
	if fh.Name != "solid.bin" {
		t.Fatalf("reached %q; want solid.bin", fh.Name)
	}
}

// TestSkipDamagedFile_ResetClearsDamage pins that damage belongs to the stream
// that caused it. A reused decompressor refusing the next archive's solid
// files over an unrelated failure would be a leak of exactly the kind Reset
// exists to prevent.
func TestSkipDamagedFile_ResetClearsDamage(t *testing.T) {
	var damagedArchive bytes.Buffer
	damagedArchive.Write(rar5ArchiveHeader())
	damagedArchive.Write(shortEntry("truncated.bin"))
	damagedArchive.Write(rar5EndHeader())

	sd := decompressorFor(damagedArchive.Bytes())
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the damaged file: %v", err)
	}
	var fe *FileError
	if _, err := sd.Next(); !errors.As(err, &fe) {
		t.Fatalf("want *FileError, got %v", err)
	}
	if !sd.damaged {
		t.Fatal("the damaged state was never set, so this cannot test clearing it")
	}

	content := []byte("a fresh archive, solid from the start")
	var fresh bytes.Buffer
	fresh.Write(rar5ArchiveHeader())
	fresh.Write(rar5EntryComp("solid.bin", FileCompSolid, uint64(len(content)),
		crc32.ChecksumIEEE(content), content))
	fresh.Write(rar5EndHeader())

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(fresh.Bytes())}
	close(volumes)
	sd.Reset(volumes)

	if sd.damaged {
		t.Fatal("Reset left the previous stream's damage in place")
	}
	if _, err := sd.Next(); err != nil {
		t.Fatalf("a solid file in a fresh archive returned %v; the previous "+
			"stream's damage must not reach it", err)
	}
}

// TestSkipDamagedFile_FailedDrainIsNotContinuable pins the limit of the
// promise. FileError says the stream is positioned at the next block. When the
// drain itself fails that is not known, and inviting the caller to read on
// from an unknown offset is how a block header gets parsed out of a previous
// file's payload -- the fabrication this library refuses elsewhere.
//
// Truncated media is deliberately NOT this case: packedCursor.drain treats a
// short drain as success, because the promised bytes were simply never there
// and the stream is left at the end of the volume, which is a position the
// traversal understands. Only a reader that errors leaves the offset unknown.
func TestSkipDamagedFile_FailedDrainIsNotContinuable(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	full := archive.Bytes()

	readErr := errors.New("media failed mid-payload")
	// Serve everything up to the last few payload bytes, then fail rather than
	// report EOF, so the drain cannot complete and cannot conclude the volume
	// simply ended.
	src := &errAfterBytes{data: full, failAt: len(full) - 4, err: readErr}

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{src}
	close(volumes)
	sd := NewStreamDecompressor(volumes)

	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	_, _ = io.Copy(io.Discard, sd)

	_, err := sd.Next()
	if err == nil {
		t.Fatal("a failed drain reported success")
	}
	var fe *FileError
	if errors.As(err, &fe) {
		t.Fatalf("Next returned a continuable *FileError (%v) after the drain "+
			"failed; the stream offset is unknown, so reading on risks parsing "+
			"a header out of payload", err)
	}
	if sd.damaged {
		t.Error("a file whose drain failed was recorded as merely damaged; " +
			"that state exists to allow continuation, which is not safe here")
	}
}
