package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// The builders below differ from the ones in crc_verify_test.go in exactly
// one way that matters here: a block's on-stream payload length and the
// file's declared unpacked size are set independently. Every other builder
// derives one from the other, which is why no existing test could express an
// entry whose packed block outlives its decompressed content.

func rar5Block(payload []byte) []byte {
	sizeV := EncodeVint(uint64(len(payload)))
	var hashed bytes.Buffer
	hashed.Write(sizeV)
	hashed.Write(payload)
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, crc32.ChecksumIEEE(hashed.Bytes()))
	out.Write(hashed.Bytes())
	return out.Bytes()
}

func rar5ArchiveHeader() []byte {
	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeArchive))
	p.Write(EncodeVint(0))
	p.Write(EncodeVint(ArcFlagMultiVol))
	var out bytes.Buffer
	out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	out.Write(rar5Block(p.Bytes()))
	return out.Bytes()
}

func rar5EndHeader() []byte {
	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeEnd))
	p.Write(EncodeVint(0))
	return rar5Block(p.Bytes())
}

// rar5FileEntry emits a store-method file block plus its payload. dataSize is
// taken from len(payload), so passing a payload longer than unpackedSize
// produces an entry whose packed block has bytes left over once the declared
// content has been produced.
func rar5FileEntry(name string, unpackedSize uint64, declaredCRC uint32, payload []byte) []byte {
	return rar5EntryComp(name, 0, unpackedSize, declaredCRC, payload)
}

// rar5EntryComp is rar5FileEntry with the compression-info vint exposed, so a
// test can set FileCompSolid (0x40) or a method without rebuilding the block.
// Method lives in bits 7-9 of the same vint, so 0 is store either way.
func rar5EntryComp(name string, compFlags uint64, unpackedSize uint64, declaredCRC uint32, payload []byte) []byte {
	return rar5EntryFlags(name, compFlags, HeaderFlagHasData, unpackedSize, declaredCRC, payload)
}

// rar5EntryFlags is rar5EntryComp with the BLOCK header flags exposed as well,
// so a test can mark an entry as continuing into the next volume
// (HeaderFlagDataNotLast) without restating the header layout.
func rar5EntryFlags(name string, compFlags uint64, blockFlags uint64, unpackedSize uint64, declaredCRC uint32, payload []byte) []byte {
	var fp bytes.Buffer
	fp.Write(EncodeVint(FileFlagHasCRC32))
	fp.Write(EncodeVint(unpackedSize))
	fp.Write(EncodeVint(0))
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], declaredCRC)
	fp.Write(crcBuf[:])
	fp.Write(EncodeVint(compFlags))
	fp.Write(EncodeVint(1))
	fp.Write(EncodeVint(uint64(len(name))))
	fp.WriteString(name)

	var hp bytes.Buffer
	hp.Write(EncodeVint(HeaderTypeFile))
	hp.Write(EncodeVint(blockFlags))
	hp.Write(EncodeVint(uint64(len(payload))))
	hp.Write(fp.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(hp.Bytes()))
	out.Write(payload)
	return out.Bytes()
}

// TestPackedRemainder_RAR5FabricatedHeaderIsRefused is the reproduction for
// the header-fabrication path. A file whose declared UnpackedSize is smaller
// than its block's DataSize completes successfully, leaving the trailing
// payload to be parsed as the next block header. Those trailing bytes are
// attacker-chosen and can carry a well-formed, CRC-valid file header, so
// NextEntry would otherwise hand back an entry that exists nowhere in the
// archive's real structure.
//
// The archive is byte-for-byte legitimate up to the point of the lie: only
// the relationship between UnpackedSize and DataSize is abnormal, and
// nothing rejected it -- the rar-bomb guard checks the opposite ratio.
//
// The property is positional recovery: what NextEntry reaches after the
// oversized block is the archive's genuine next entry, not merely "an
// error" (equally true of vulnerable code) and not merely "some entry other
// than EVIL.txt" (satisfied by consuming too much or too little).
func TestPackedRemainder_RAR5FabricatedHeaderIsRefused(t *testing.T) {
	evil := rar5FileEntry("EVIL.txt", 5, crc32.ChecksumIEEE([]byte("PWNED")), []byte("PWNED"))

	content := []byte("0123456789")
	payload := append(append([]byte{}, content...), evil...)

	var arc bytes.Buffer
	arc.Write(rar5ArchiveHeader())
	arc.Write(rar5FileEntry("benign.txt", uint64(len(content)),
		crc32.ChecksumIEEE(content), payload))
	arc.Write(rar5FileEntry("real_next.bin", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	arc.Write(rar5EndHeader())

	r := readerFor(arc.Bytes())

	e1, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if e1.Header.Name != "benign.txt" {
		t.Fatalf("Next#1 = %q, want benign.txt", e1.Header.Name)
	}
	if got, err := io.ReadAll(e1); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("reading benign.txt = %q, %v; want %q, nil", got, err, content)
	}
	_ = e1.Close()

	e2, err := r.NextEntry() // Must cleanly reach the real next entry, never the planted payload
	if err != nil || e2.Header.Name != "real_next.bin" {
		t.Fatalf("failed to reach genuine next entry: %v", err)
	}
}

// TestPackedRemainder_ConsumedOnCompletion pins the mechanism rather than the
// symptom: after a file ends, none of its packed block may still be owed.
// Asserting the byte count separately from the fabrication test above means
// a fix that merely stops one particular fabricated header from parsing --
// without consuming the trailing bytes exactly -- still fails here, because a
// sentinel header planted right after the padding can only be reached by
// consuming precisely as many bytes as were declared, neither fewer nor more.
func TestPackedRemainder_ConsumedOnCompletion(t *testing.T) {
	content := []byte("0123456789")
	payload := append(append([]byte{}, content...), bytes.Repeat([]byte{0xAA}, 31)...)

	var arc bytes.Buffer
	arc.Write(rar5ArchiveHeader())
	arc.Write(rar5FileEntry("benign.txt", uint64(len(content)),
		crc32.ChecksumIEEE(content), payload))
	arc.Write(rar5FileEntry("sentinel.bin", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	arc.Write(rar5EndHeader())

	r := readerFor(arc.Bytes())
	e1, err := r.NextEntry()
	if err != nil {
		t.Fatalf("Next#1: %v", err)
	}
	if _, err := io.ReadAll(e1); err != nil {
		t.Fatalf("reading: %v", err)
	}
	_ = e1.Close()

	e2, err := r.NextEntry()
	if err != nil {
		t.Fatalf("Next#2: %v", err)
	}
	if e2.Header.Name != "sentinel.bin" {
		t.Errorf("reached %q, want sentinel.bin: the packed block's trailing "+
			"padding was not fully consumed, so the next header would be "+
			"parsed from the wrong offset", e2.Header.Name)
	}
}

// recordingVolume reports whether the library read from it after being told,
// through Close, that the library was finished with it.
type recordingVolume struct {
	r               *bytes.Reader
	closed          bool
	readsAfterClose int
}

func (v *recordingVolume) Read(p []byte) (int, error) {
	if v.closed {
		v.readsAfterClose++
	}
	return v.r.Read(p)
}

func (v *recordingVolume) Close() error {
	v.closed = true
	return nil
}

// TestPackedRemainder_NoReadAfterVolumeClose covers the interaction between
// draining and volume exhaustion. nextVolume closes the current volume before
// it can discover the channel holds no further volume, so a file whose payload
// continues off the end of the last volume leaves a count standing against a
// reader that is already closed.
//
// Draining it there would read a caller-supplied io.ReadCloser after telling
// the caller it was finished: a bytes.Reader tolerates that, an *os.File
// returns "file already closed", and a pooled or network-backed stream may
// hand back somebody else's bytes. A partially downloaded multi-volume set is
// the ordinary case for this library's callers, not a crafted one.
func TestPackedRemainder_NoReadAfterVolumeClose(t *testing.T) {
	b := fixtureBytes(t, "rar5_multi.part01.rar")
	vol := &recordingVolume{r: bytes.NewReader(b[:len(b)-300])}

	volumes := make(chan io.ReadCloser, 1)
	volumes <- vol
	close(volumes)

	r := NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry#1: %v", err)
	}
	_, _ = io.ReadAll(e)
	if _, err := r.NextEntry(); err == nil {
		t.Fatal("NextEntry#2 succeeded; want the archive to end")
	}

	// Asserted, not assumed. If the file no longer runs past the end of this
	// volume, nothing closes it and "no reads after close" holds trivially.
	if !vol.closed {
		t.Fatal("the volume was never closed, so this test would pass without " +
			"exercising the path it names")
	}
	if vol.readsAfterClose != 0 {
		t.Errorf("read from the volume %d times after closing it",
			vol.readsAfterClose)
	}
}

// TestPackedRemainder_NoJoinOnCleanArchiveEnd guards the error value a caller
// actually sees when a multi-volume set simply runs out. Wrapping that in a
// join would break identity comparisons against the sentinel, which is how
// several loops in this repo decide the archive is over.
func TestPackedRemainder_NoJoinOnCleanArchiveEnd(t *testing.T) {
	// Untrimmed: the archive is healthy and read to completion, so the only
	// thing left to report is that no further volume exists.
	r := NewReader(multiVolumeChan(t, -1))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry#1: %v", err)
	}
	if _, err := io.ReadAll(e); err != nil {
		t.Fatalf("reading: %v", err)
	}

	_, err = r.NextEntry()
	//nolint:errorlint // identity is the property under test, not equivalence.
	if err != ErrNoNextVolume {
		t.Errorf("NextEntry at the end of a healthy archive returned %v (%T); "+
			"want the bare ErrNoNextVolume sentinel. Wrapping it in a join "+
			"breaks the identity comparisons callers use to stop looping", err, err)
	}
}

// TestRefusedFile_RarBombPayloadIsDropped covers a refusal that is not a parse
// failure. The rar-bomb guard rejects the file after its header has been read,
// but traversal continues -- the caller can and does call Next() again -- so
// leaving the payload lets the block that was just refused supply the next
// entry. The fabricated entry carries its own valid CRC32, because whoever
// wrote the payload computed it.
func TestRefusedFile_RarBombPayloadIsDropped(t *testing.T) {
	evil := rar5FileEntry("EVIL.txt", 5, crc32.ChecksumIEEE([]byte("PWNED")), []byte("PWNED"))

	var arc bytes.Buffer
	arc.Write(rar5ArchiveHeader())
	// UnpackedSize is over the 1 MiB floor and more than 1000x the packed
	// size, which is what the guard rejects.
	arc.Write(rar5FileEntry("bomb.txt", 2_000_000, 0, evil))
	arc.Write(rar5EndHeader())

	r := readerFor(arc.Bytes())

	e1, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry#1: %v", err)
	}
	if closeErr := e1.Close(); !errors.Is(closeErr, ErrRarBombDetected) {
		t.Fatalf("Close#1 = %v; want ErrRarBombDetected", closeErr)
	}
	e2, err := r.NextEntry()
	if err == nil {
		t.Fatalf("NextEntry#2 surfaced %q out of the refused file's payload; "+
			"want an error", e2.Header.Name)
	}
}

// TestRefusedFile_CorruptHeaderPayloadIsDropped covers parse failures other
// than the one that already dropped its payload. Which field an archive
// corrupts is the archive's choice, so keying the discard on a single named
// error left the same fabrication reachable through every other one.
//
// A negative UnpackedSize is decoded well after the name, so it is now
// refused BY NAME as a terminal Entry (identity-first validation) rather
// than as a bare NextEntry error -- the fixture below already carries a
// complete header through the name field, so the refusal happens at the
// validation block in parseFileHeader rather than at the earlier decode.
func TestRefusedFile_CorruptHeaderPayloadIsDropped(t *testing.T) {
	evil := rar5FileEntry("EVIL.txt", 5, crc32.ChecksumIEEE([]byte("PWNED")), []byte("PWNED"))

	// An UnpackedSize vint with the int64 sign bit set is refused by the
	// parser as a corrupt header.
	var fp bytes.Buffer
	fp.Write(EncodeVint(FileFlagHasCRC32))
	fp.Write(EncodeVint(1 << 63))
	fp.Write(EncodeVint(0))
	fp.Write([]byte{0, 0, 0, 0})
	fp.Write(EncodeVint(0))
	fp.Write(EncodeVint(1))
	fp.Write(EncodeVint(uint64(len("neg.txt"))))
	fp.WriteString("neg.txt")

	var hp bytes.Buffer
	hp.Write(EncodeVint(HeaderTypeFile))
	hp.Write(EncodeVint(HeaderFlagHasData))
	hp.Write(EncodeVint(uint64(len(evil))))
	hp.Write(fp.Bytes())

	var arc bytes.Buffer
	arc.Write(rar5ArchiveHeader())
	arc.Write(rar5Block(hp.Bytes()))
	arc.Write(evil)
	arc.Write(rar5EndHeader())

	r := readerFor(arc.Bytes())

	e1, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry#1: %v", err)
	}
	if e1 == nil || e1.Header == nil || e1.Header.Name != "neg.txt" {
		t.Fatalf("NextEntry#1 returned %+v, want the refused member reported by name (neg.txt)", e1)
	}
	if closeErr := e1.Close(); !errors.Is(closeErr, ErrCorruptFileHeader) {
		t.Fatalf("Close#1 = %v; want ErrCorruptFileHeader", closeErr)
	}

	e2, err := r.NextEntry()
	if e2 != nil {
		t.Fatalf("NextEntry#2 surfaced %q out of the refused file's payload; "+
			"want end of archive", e2.Header.Name)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("NextEntry#2 error = %v, want io.EOF or ErrNoNextVolume", err)
	}
}

// TestPackedRemainder_TracksCurrentVolume is deleted, not translated.
//
// What it asserted: it read a healthy multi-volume archive far enough to
// cross a volume boundary mid-file (sd.currentVol != first), then reached
// into the engine's internals and compared re.packed.lr.R -- the
// io.LimitedReader field packedCursor's payload draining reads through --
// against sd.currentVol by pointer identity, failing if they had drifted
// apart. Its subject was therefore packedCursor itself: a limiter object,
// installed fresh on each volume advance, that the old engine had to
// remember to re-fetch or it would drain a later volume's legitimate header
// bytes as though they belonged to the file in progress. packedCursor does
// not survive this rewrite (see CLAUDE.md and the task-12 brief, which name
// it explicitly as deleted).
//
// The invariant it guarded is now structurally rather than procedurally
// true: multiVolumePayloadReader.Read reassigns its src directly to
// r.vol.payload() on every volume boundary (splice.go, nextVolumePayload),
// and volume.body lives inside the volume itself rather than in a separate
// object that can be constructed and then forgotten. There is no second
// reference for a drain to read through by mistake, so the bug class this
// test caught cannot occur by construction. Reading a real file across a
// volume boundary is exercised end to end by TestIntegration_MultiVolume and
// by TestPackedRemainder_NoReadAfterVolumeClose above.
