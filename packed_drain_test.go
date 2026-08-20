package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// The builders below differ from the ones in crc_verify_test.go and
// decompressor_rar3_test.go in exactly one way that matters here: a block's
// on-stream payload length and the file's declared unpacked size are set
// independently. Every other builder derives one from the other, which is
// why no existing test could express an entry whose packed block outlives
// its decompressed content.

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

// rar3FileEntry is the RAR3 equivalent, with PACK_SIZE and UNP_SIZE set
// independently for the same reason.
func rar3FileEntry(name string, unpackedSize uint32, declaredCRC uint32, payload []byte) []byte {
	return rar3StoreEntry(name, 0, unpackedSize, declaredCRC, payload)
}

// rar3StoreEntry is rar3FileEntry with the extra header flags exposed, so a
// test can vary one bit and hold everything else fixed.
//
// Setting LHD_PASSWORD (0x0400) appends the 8 salt bytes that follow the name,
// because ParseRAR3FileHeader reads them there and a header claiming
// encryption without them is rejected as corrupt rather than exercising
// anything.
func rar3StoreEntry(name string, extraFlags uint16, unpackedSize uint32, declaredCRC uint32, payload []byte) []byte {
	headSize := 32 + len(name)
	if extraFlags&0x0400 > 0 {
		headSize += 8
	}
	h := make([]byte, headSize)
	h[2] = 0x74
	// 0x8000 is LHD_LARGE-free framing carrying ADD_SIZE.
	binary.LittleEndian.PutUint16(h[3:5], 0x8000|extraFlags)
	binary.LittleEndian.PutUint16(h[5:7], uint16(headSize))
	binary.LittleEndian.PutUint32(h[7:11], uint32(len(payload))) // PACK_SIZE
	binary.LittleEndian.PutUint32(h[11:15], unpackedSize)        // UNP_SIZE
	h[15] = 3
	binary.LittleEndian.PutUint32(h[16:20], declaredCRC)
	binary.LittleEndian.PutUint32(h[20:24], 0)
	h[24] = 20
	h[25] = 0x30 // store
	binary.LittleEndian.PutUint16(h[26:28], uint16(len(name)))
	binary.LittleEndian.PutUint32(h[28:32], 0o644)
	copy(h[32:], name)
	binary.LittleEndian.PutUint16(h[0:2], uint16(crc32.ChecksumIEEE(h[2:])))

	var out bytes.Buffer
	out.Write(h)
	out.Write(payload)
	return out.Bytes()
}

// rar3LargeFileEntry emits a file block carrying LHD_LARGE, which splits both
// sizes across a low half in the ordinary fields and a high half in
// HIGH_PACK_SIZE / HIGH_UNP_SIZE. The block framing's ADD_SIZE holds only the
// low half of the packed size, so a reader that trusts it alone sees a
// different figure than the header actually declares.
func rar3LargeFileEntry(name string, unpLow, highPack, highUnp, declaredCRC uint32, payload []byte) []byte {
	const large = 0x0100
	headSize := 40 + len(name)
	h := make([]byte, headSize)
	h[2] = 0x74
	binary.LittleEndian.PutUint16(h[3:5], 0x8000|large)
	binary.LittleEndian.PutUint16(h[5:7], uint16(headSize))
	binary.LittleEndian.PutUint32(h[7:11], uint32(len(payload))) // ADD_SIZE: low half only
	binary.LittleEndian.PutUint32(h[11:15], unpLow)
	h[15] = 3
	binary.LittleEndian.PutUint32(h[16:20], declaredCRC)
	binary.LittleEndian.PutUint32(h[20:24], 0)
	h[24] = 20
	h[25] = 0x30
	binary.LittleEndian.PutUint16(h[26:28], uint16(len(name)))
	binary.LittleEndian.PutUint32(h[28:32], 0o644)
	binary.LittleEndian.PutUint32(h[32:36], highPack)
	binary.LittleEndian.PutUint32(h[36:40], highUnp)
	copy(h[40:], name)
	binary.LittleEndian.PutUint16(h[0:2], uint16(crc32.ChecksumIEEE(h[2:])))

	var out bytes.Buffer
	out.Write(h)
	out.Write(payload)
	return out.Bytes()
}

func rar3ArchiveHeader() []byte {
	m := make([]byte, 13)
	m[2] = 0x73
	binary.LittleEndian.PutUint16(m[5:7], 13)
	binary.LittleEndian.PutUint16(m[0:2], uint16(crc32.ChecksumIEEE(m[2:])))
	var out bytes.Buffer
	out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00})
	out.Write(m)
	return out.Bytes()
}

// TestPackedRemainder_RAR5FabricatedHeaderIsRefused is the reproduction for
// the header-fabrication path. A file whose declared UnpackedSize is smaller
// than its block's DataSize completes successfully, leaving the trailing
// payload to be parsed as the next block header. Those trailing bytes are
// attacker-chosen and can carry a well-formed, CRC-valid file header, so
// Next() hands back an entry that exists nowhere in the archive's real
// structure.
//
// The archive is byte-for-byte legitimate up to the point of the lie: only
// the relationship between UnpackedSize and DataSize is abnormal, and
// nothing rejected it -- the rar-bomb guard checks the opposite ratio.
func TestPackedRemainder_RAR5FabricatedHeaderIsRefused(t *testing.T) {
	evil := rar5FileEntry("EVIL.txt", 5, crc32.ChecksumIEEE([]byte("PWNED")), []byte("PWNED"))

	content := []byte("0123456789")
	payload := append(append([]byte{}, content...), evil...)

	var arc bytes.Buffer
	arc.Write(rar5ArchiveHeader())
	arc.Write(rar5FileEntry("benign.txt", uint64(len(content)),
		crc32.ChecksumIEEE(content), payload))
	arc.Write(rar5EndHeader())

	sd := decompressorFor(arc.Bytes())

	fh1, err := sd.Next()
	if err != nil {
		t.Fatalf("Next#1: %v", err)
	}
	if fh1.Name != "benign.txt" {
		t.Fatalf("Next#1 = %q, want benign.txt", fh1.Name)
	}
	if got, err := io.ReadAll(sd); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("reading benign.txt = %q, %v; want %q, nil", got, err, content)
	}

	fh2, err2 := sd.Next()
	if err2 == nil {
		t.Fatalf("Next#2 surfaced fabricated entry %q; want an error", fh2.Name)
	}
}

// TestPackedRemainder_RAR3FabricatedHeaderIsRefused is the same reproduction
// against the RAR3 engine, which has the identical block-walking structure
// and so had the identical hole.
func TestPackedRemainder_RAR3FabricatedHeaderIsRefused(t *testing.T) {
	evil := rar3FileEntry("EVIL.txt", 5, crc32.ChecksumIEEE([]byte("PWNED")), []byte("PWNED"))

	content := []byte("0123456789")
	payload := append(append([]byte{}, content...), evil...)

	var arc bytes.Buffer
	arc.Write(rar3ArchiveHeader())
	arc.Write(rar3FileEntry("benign.txt", uint32(len(content)),
		crc32.ChecksumIEEE(content), payload))

	sd := decompressorFor(arc.Bytes())

	fh1, err := sd.Next()
	if err != nil {
		t.Fatalf("Next#1: %v", err)
	}
	if fh1.Name != "benign.txt" {
		t.Fatalf("Next#1 = %q, want benign.txt", fh1.Name)
	}
	if got, err := io.ReadAll(sd); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("reading benign.txt = %q, %v; want %q, nil", got, err, content)
	}

	fh2, err2 := sd.Next()
	if err2 == nil {
		t.Fatalf("Next#2 surfaced fabricated entry %q; want an error", fh2.Name)
	}
}

// TestPackedRemainder_ConsumedOnCompletion pins the mechanism rather than the
// symptom: after a file ends, none of its packed block may still be owed.
// Asserting the byte count separately from the fabrication tests above means
// a fix that merely stops the fabricated entry from parsing -- without
// consuming the bytes -- still fails here.
func TestPackedRemainder_ConsumedOnCompletion(t *testing.T) {
	content := []byte("0123456789")
	payload := append(append([]byte{}, content...), bytes.Repeat([]byte{0xAA}, 31)...)

	var arc bytes.Buffer
	arc.Write(rar5ArchiveHeader())
	arc.Write(rar5FileEntry("benign.txt", uint64(len(content)),
		crc32.ChecksumIEEE(content), payload))
	arc.Write(rar5EndHeader())

	sd := decompressorFor(arc.Bytes())
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next#1: %v", err)
	}
	if _, err := io.ReadAll(sd); err != nil {
		t.Fatalf("reading: %v", err)
	}
	_, _ = sd.Next()

	re, ok := sd.engine.(*rar5Engine)
	if !ok {
		t.Fatalf("engine is %T, want *rar5Engine", sd.engine)
	}
	if owed := re.packed.owed(); owed != 0 {
		t.Errorf("packed cursor still owes %d bytes after the file ended, want 0: "+
			"the next header would be parsed from them", owed)
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

	sd := NewStreamDecompressor(volumes)
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next#1: %v", err)
	}
	_, _ = io.ReadAll(sd)
	if _, err := sd.Next(); err == nil {
		t.Fatal("Next#2 succeeded; want the archive to end")
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
	sd := NewStreamDecompressor(multiVolumeChan(t, -1))

	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next#1: %v", err)
	}
	if _, err := io.ReadAll(sd); err != nil {
		t.Fatalf("reading: %v", err)
	}

	_, err := sd.Next()
	//nolint:errorlint // identity is the property under test, not equivalence.
	if err != ErrNoNextVolume {
		t.Errorf("Next at the end of a healthy archive returned %v (%T); want "+
			"the bare ErrNoNextVolume sentinel. Wrapping it in a join breaks "+
			"the identity comparisons callers use to stop looping", err, err)
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

	sd := decompressorFor(arc.Bytes())

	if _, err := sd.Next(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Next#1 = %v; want ErrRarBombDetected", err)
	}
	fh, err := sd.Next()
	if err == nil {
		t.Fatalf("Next#2 surfaced %q out of the refused file's payload; "+
			"want an error", fh.Name)
	}
}

// TestRefusedFile_CorruptHeaderPayloadIsDropped covers parse failures other
// than the one that already dropped its payload. Which field an archive
// corrupts is the archive's choice, so keying the discard on a single named
// error left the same fabrication reachable through every other one.
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

	sd := decompressorFor(arc.Bytes())

	if _, err := sd.Next(); err == nil {
		t.Fatal("Next#1 accepted a header with a negative unpacked size")
	}
	fh, err := sd.Next()
	if err == nil {
		t.Fatalf("Next#2 surfaced %q out of the refused file's payload; "+
			"want an error", fh.Name)
	}
}

// TestRefusedFile_RarBombPayloadIsDroppedRAR3 is the RAR3 counterpart of the
// RAR5 rar-bomb test. The guard exists in both engines and so did the leak.
func TestRefusedFile_RarBombPayloadIsDroppedRAR3(t *testing.T) {
	evil := rar3FileEntry("EVIL.txt", 5, crc32.ChecksumIEEE([]byte("PWNED")), []byte("PWNED"))

	var arc bytes.Buffer
	arc.Write(rar3ArchiveHeader())
	// Over the 1 MiB floor and more than 1000x the packed size.
	arc.Write(rar3FileEntry("bomb.txt", 2_000_000, 0, evil))

	sd := decompressorFor(arc.Bytes())

	if _, err := sd.Next(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Next#1 = %v; want ErrRarBombDetected", err)
	}
	fh, err := sd.Next()
	if err == nil {
		t.Fatalf("Next#2 surfaced %q out of the refused file's payload; "+
			"want an error", fh.Name)
	}
}

// TestRefusedFile_RarBombDiscardsFullRAR3PackedSize covers the half of a RAR3
// packed size that the block framing does not carry.
//
// RAR3 splits a large file's packed size between ADD_SIZE and HIGH_PACK_SIZE,
// and the block header exposes only the low half. Discarding that alone
// leaves the high half unaccounted for, and the next header is then read from
// wherever the stream happens to sit.
//
// A real >4 GiB payload cannot be built here, so the archive below declares
// one and supplies a few bytes. The declared size is what the refusal must
// honour: consuming it runs to the end of the volume and takes the following
// entry with it, which is the conservative direction -- an archive that lies
// about its size loses the rest of itself rather than choosing what the
// library parses next. Trusting the low half instead leaves the stream
// positioned exactly on the entry after it, which is what this asserts
// against.
func TestRefusedFile_RarBombDiscardsFullRAR3PackedSize(t *testing.T) {
	filler := bytes.Repeat([]byte{0xAA}, 16)
	second := []byte("SECOND-FILE-INTACT")

	var arc bytes.Buffer
	arc.Write(rar3ArchiveHeader())
	// PackedSize = 16 | (1 << 32); UnpackedSize = 1001 << 32, which clears
	// both the 1 MiB floor and the 1000x ratio the guard rejects.
	arc.Write(rar3LargeFileEntry("big.bin", 0, 1, 1001, 0, filler))
	arc.Write(rar3FileEntry("second.txt", uint32(len(second)),
		crc32.ChecksumIEEE(second), second))

	sd := decompressorFor(arc.Bytes())

	if _, err := sd.Next(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Next#1 = %v; want ErrRarBombDetected", err)
	}
	fh, err := sd.Next()
	if err == nil {
		t.Fatalf("Next#2 returned %q; the refusal discarded only the low half "+
			"of the declared packed size, leaving the stream positioned on "+
			"whatever followed", fh.Name)
	}
}

// TestPackedRemainder_TracksCurrentVolume pins the invariant that makes the
// drain safe on multi-volume files: while any packed bytes are still owed,
// the limiter holding that count must describe the volume actually being
// read. It did not, because each volume advance installed a fresh limiter
// that the engine never saw again -- so a drain would have consumed the
// count from a later volume's legitimate header bytes.
func TestPackedRemainder_TracksCurrentVolume(t *testing.T) {
	// Healthy archive, stopped mid-file: the read is large enough to have
	// crossed several volume boundaries and small enough that the file is
	// still in progress, which is the only state where the cursor both owes
	// bytes and has had to follow the stream onto another volume.
	sd := NewStreamDecompressor(multiVolumeChan(t, -1))

	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	first := sd.currentVol
	if _, err := io.ReadFull(sd, make([]byte, 4096)); err != nil {
		t.Fatalf("reading the first half of the file: %v", err)
	}

	re, ok := sd.engine.(*rar5Engine)
	if !ok {
		t.Fatalf("engine is %T, want *rar5Engine", sd.engine)
	}
	// Asserted, not assumed. Everything below is about what happens when a
	// file crosses a volume boundary, so a read that never crossed one would
	// satisfy the check while proving nothing.
	if sd.currentVol == first {
		t.Fatal("the read never left the first volume, so this test would " +
			"pass without exercising the invariant it names")
	}
	if re.packed.lr.R != sd.currentVol {
		t.Error("the packed cursor points at a volume the stream has already " +
			"left; draining it would consume bytes from the wrong one")
	}
}
