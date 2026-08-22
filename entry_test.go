package rarengine

import (
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

func entryOver(content string, fh *FileHeader) *Entry {
	return newEntry(fh, strings.NewReader(content))
}

func headerFor(content string, withCRC bool) *FileHeader {
	fh := &FileHeader{
		Name:         "f.bin",
		UnpackedSize: int64(len(content)),
		LastBlock:    true,
	}
	if withCRC {
		fh.HasCRC32 = true
		fh.CRC32 = crc32.ChecksumIEEE([]byte(content))
	}
	return fh
}

// A member that delivers its declared size with a matching checksum ends as
// io.EOF, and Close agrees.
func TestEntryCleanReadEndsWithEOF(t *testing.T) {
	const content = "hello world"
	e := entryOver(content, headerFor(content, true))

	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close after clean read = %v, want nil", err)
	}
}

// The verdict must be reachable from Read as well as Close, so a member never
// completes silently whichever way the caller drives it.
func TestEntryCRCMismatchReportedByBothReadAndClose(t *testing.T) {
	const content = "hello world"
	fh := headerFor(content, true)
	fh.CRC32 ^= 0xffffffff // wrong on purpose
	e := entryOver(content, fh)

	_, err := io.Copy(io.Discard, e)
	if !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Read verdict = %v, want ErrCRCMismatch", err)
	}
	if err := e.Close(); !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Close verdict = %v, want ErrCRCMismatch", err)
	}
}

// A source that ends before the declared size is truncation, and truncation
// must never read as a clean end of stream.
func TestEntryTruncationIsNotEOF(t *testing.T) {
	fh := headerFor("hello world", false)
	fh.UnpackedSize = 100 // claims more than the source has
	e := entryOver("hello world", fh)

	_, err := io.Copy(io.Discard, e)
	if !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("verdict = %v, want ErrTruncatedFile", err)
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("ErrTruncatedFile must not satisfy errors.Is(err, io.EOF): " +
			"callers loop until io.EOF, so that restores the silent-truncation bug")
	}
}

// Once a member has failed, it stays failed. A caller told the member is bad
// must not then receive bytes from it.
func TestEntryTerminalErrorIsDurable(t *testing.T) {
	const content = "hello world"
	fh := headerFor(content, true)
	fh.CRC32 ^= 0xffffffff
	e := entryOver(content, fh)

	_, _ = io.Copy(io.Discard, e)

	buf := make([]byte, 8)
	n, err := e.Read(buf)
	if n != 0 {
		t.Fatalf("Read after failure returned %d bytes, want 0", n)
	}
	if !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Read after failure = %v, want the recorded ErrCRCMismatch", err)
	}
}

// A refused member is still an Entry, so NextEntry's error set stays
// archive-level only.
func TestTerminalEntryReportsItsCause(t *testing.T) {
	fh := &FileHeader{Name: "bomb.bin"}
	e := terminalEntry(fh, ErrRarBombDetected)

	if e.Header != fh {
		t.Fatal("terminal entry must carry the header that names the member")
	}
	buf := make([]byte, 8)
	if _, err := e.Read(buf); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Read = %v, want ErrRarBombDetected", err)
	}
	if err := e.Close(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Close = %v, want ErrRarBombDetected", err)
	}
}

// A zero-length member never enters the read path, so completing it here is
// what gives it a terminal state at all.
func TestEntryZeroLengthCompletes(t *testing.T) {
	e := entryOver("", headerFor("", false))
	n, err := e.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read = (%d, %v), want (0, io.EOF)", n, err)
	}
}

// A header whose declared size is negative -- a 70-bit RAR5 size vint can set
// the sign bit -- must not reach the slice clamp in Read.
func TestEntryNegativeSizeDoesNotPanic(t *testing.T) {
	fh := headerFor("", false)
	fh.UnpackedSize = -1
	e := entryOver("data", fh)

	n, err := e.Read(make([]byte, 8))
	if n != 0 {
		t.Fatalf("Read returned %d bytes for a negative declared size", n)
	}
	if err == nil {
		t.Fatal("Read on a negative declared size must report a verdict")
	}
}

// advanceVolume is the one place allowed to swap the header in force
// mid-member, and lastBlock reads it back -- the splice's way of telling a
// real end from a volume boundary.
func TestEntryAdvanceVolumeChangesLastBlock(t *testing.T) {
	fh := headerFor("hello world", true)
	fh.LastBlock = false
	e := entryOver("hello world", fh)

	if e.lastBlock() {
		t.Fatal("lastBlock() = true before the final part's header is in force")
	}

	next := headerFor("", false)
	next.LastBlock = true
	e.advanceVolume(next)

	if !e.lastBlock() {
		t.Fatal("lastBlock() = false after advanceVolume to a header with LastBlock set")
	}
}

// short reports whether the member stopped before its declared size --
// false while bytes remain undelivered, false again once they are all read,
// and true only when a short Read leaves the budget unmet.
func TestEntryShortReflectsRemainingBudget(t *testing.T) {
	const content = "hello world"
	e := entryOver(content, headerFor(content, true))

	if !e.short() {
		t.Fatal("short() = false before any bytes have been read")
	}

	if _, err := io.ReadAll(e); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if e.short() {
		t.Fatal("short() = true after the full declared size was delivered")
	}
}

func TestEntryShortAfterTruncation(t *testing.T) {
	fh := headerFor("hello world", false)
	fh.UnpackedSize = 100
	e := entryOver("hello world", fh)

	_, _ = io.Copy(io.Discard, e)
	if !e.short() {
		t.Fatal("short() = false after a truncated read left bytes owed")
	}
}
