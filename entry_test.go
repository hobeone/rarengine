package rarengine

import (
	"errors"
	"fmt"
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

// short reports whether the member's declared size is still unmet, which is
// true from the moment it is created -- before a single byte has been read --
// and becomes false only once every declared byte has been delivered. It is a
// statement about the budget, not about whether a Read has failed, which is
// why finishActive can consult it on a member the caller merely abandoned.
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

// Close must compare the recorded verdict to io.EOF by identity, not with
// errors.Is. finish only ever assigns the bare io.EOF sentinel on success, so
// no production path can currently reach this state -- this is a white-box
// guard against a future refactor (e.g. a decoder wrapping io.EOF for
// context before handing it to finish) that would otherwise make Close
// silently report a failed member as successful.
func TestEntryCloseDoesNotTranslateWrappedEOF(t *testing.T) {
	e := entryOver("hello world", headerFor("hello world", true))
	wrapped := fmt.Errorf("decoder: %w", io.EOF)
	e.done = wrapped // unreachable via the public API today; set directly

	if got := e.Close(); got != wrapped {
		t.Fatalf("Close() = %v, want the wrapped verdict %v unchanged", got, wrapped)
	}
}

// TestEntryReadBeforeSourceIsSetReportsNoActiveFile covers the entry a
// dispatched member starts as: Reader.dispatch constructs it with a nil src
// via newEntry(fh, nil) before the decode chain is known to build
// successfully, filling e.src in only once it does. A caller that somehow
// reached Read before that point -- or a future admission path that forgets
// the fill-in -- must not get a nil-pointer panic or silently produce zero
// bytes with no error.
func TestEntryReadBeforeSourceIsSetReportsNoActiveFile(t *testing.T) {
	e := newEntry(headerFor("hello world", true), nil)

	n, err := e.Read(make([]byte, 8))
	if n != 0 {
		t.Fatalf("Read produced %d bytes with no source", n)
	}
	if !errors.Is(err, ErrNoActiveFile) {
		t.Fatalf("Read with no source = %v, want ErrNoActiveFile", err)
	}
}

// TestMemberCompletingOnANonFinalHeaderIsRefused pins that a member cannot
// complete while a header saying it continues is still in force.
//
// Reaching the declared UnpackedSize means every byte has been produced;
// LastBlock false means the archive says more parts follow. Both cannot be
// true of a well-formed archive, and the disagreement is what made the digest
// uncomparable: the CRC32 field of a non-final part covers that part's packed
// bytes, not the file's plaintext.
//
// The old outcome was ErrCRCMismatch on content that had decoded perfectly --
// the library telling a caller its data was corrupt when every byte was
// intact. That is why this is refused rather than skipped: returning nil
// would let a malformed entry complete silently, and ErrChecksumUnsupported
// would tell a caller whose policy is "accept unverifiable" that this is an
// archive class we cannot check, rather than an archive contradicting itself.
//
// Mutation check: remove the LastBlock test from verifyChecksum and this
// fails with ErrCRCMismatch -- the false accusation, restored.
func TestMemberCompletingOnANonFinalHeaderIsRefused(t *testing.T) {
	const content = "0123456789"
	// notLast clears LastBlock. The declared size equals what this part
	// carries, so the byte budget is met while the header still claims a
	// further part. crcOf makes the recorded digest something other than the
	// plaintext CRC32, standing in for the per-part pack CRC a real
	// intermediate part records there.
	member := rar5Member(t, memberSpec{
		name: "victim.bin", content: content, withCRC: true,
		crcOf: "not the plaintext", notLast: true,
	})

	r := NewReader(volumesOf(rar5Archive(t, false, member)))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}

	got, readErr := io.ReadAll(e)
	closeErr := e.Close()

	// Every byte was delivered: the archive is malformed, not the content.
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	verdict := readErr
	if verdict == nil {
		verdict = closeErr
	}
	if errors.Is(verdict, ErrCRCMismatch) {
		t.Fatalf("verdict = %v -- correct content reported as corrupt because "+
			"a non-final part's digest was compared as the file's", verdict)
	}
	if !errors.Is(verdict, ErrCorruptFileHeader) {
		t.Fatalf("verdict = %v (read=%v close=%v), want ErrCorruptFileHeader",
			verdict, readErr, closeErr)
	}
}

// A member whose LAST part is in force at completion is unaffected: that is
// every well-formed archive, single- and multi-volume alike, and the check
// above must not cost them their checksum verification.
func TestMemberCompletingOnTheFinalHeaderStillVerifies(t *testing.T) {
	const content = "0123456789"
	member := rar5Member(t, memberSpec{
		name: "honest.bin", content: content, withCRC: true, crcOf: "wrong",
	})

	r := NewReader(volumesOf(rar5Archive(t, false, member)))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	_, _ = io.ReadAll(e)
	if err := e.Close(); !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Close = %v, want ErrCRCMismatch; a final-part digest is "+
			"still the file's and is still compared", err)
	}
}
