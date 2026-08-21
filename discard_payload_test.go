package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"testing"
)

// Tests for the invariant that no block's declared payload survives into the
// next header read.
//
// The vulnerability these cover (#48) is that a block header may declare
// payload whatever its type -- RAR5 reads DataSize whenever HeaderFlagHasData
// is set, RAR3 whenever longBlock is, and neither consults the block type -- so
// a crafted archive can put a complete, CRC-valid file entry in that region.
// Whatever fails to consume it leaves the next header to be parsed out of
// attacker-chosen bytes, and Next() hands back an entry that exists nowhere in
// the archive.
//
// Every test here asserts POSITIONAL recovery: that the entry reached after the
// refusal is the archive's genuine next one. Asserting only that the first call
// errors proves nothing, because it is equally true of the vulnerable code --
// and asserting only that the payload was "consumed" is satisfied by consuming
// too much, which is what a double-discard does.

// rar3BlockDeclaring builds a RAR3 block of the given type whose header sets
// longBlock and declares addSize bytes of payload following it.
//
// withSig prefixes the RAR3 signature, for use as the first block of an
// archive.
func rar3BlockDeclaring(blockType byte, flags uint16, addSize uint32, withSig bool) []byte {
	const hSize = 13 // 7 base + 4 ADD_SIZE + 2 header payload
	base := make([]byte, 7)
	base[2] = blockType
	binary.LittleEndian.PutUint16(base[3:5], flags|longBlock)
	binary.LittleEndian.PutUint16(base[5:7], hSize)

	var addBuf [4]byte
	binary.LittleEndian.PutUint32(addBuf[:], addSize)
	headerPayload := []byte{0x00, 0x00}

	crcBuf := append([]byte{}, base[2:]...)
	crcBuf = append(crcBuf, addBuf[:]...)
	crcBuf = append(crcBuf, headerPayload...)
	binary.LittleEndian.PutUint16(base[0:2], uint16(crc32.ChecksumIEEE(crcBuf)))

	var out bytes.Buffer
	if withSig {
		out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00})
	}
	out.Write(base)
	out.Write(addBuf[:])
	out.Write(headerPayload)
	return out.Bytes()
}

// rar5BlockDeclaring builds a RAR5 block of the given type declaring dataSize
// bytes of payload, with extra appended to the header's own fields.
func rar5BlockDeclaring(blockType uint64, dataSize int, extra []byte, withSig bool) []byte {
	var p bytes.Buffer
	p.Write(EncodeVint(blockType))
	p.Write(EncodeVint(HeaderFlagHasData))
	p.Write(EncodeVint(uint64(dataSize)))
	p.Write(extra)

	var out bytes.Buffer
	if withSig {
		out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	}
	out.Write(rar5Block(p.Bytes()))
	return out.Bytes()
}

// volumesOf returns a closed channel carrying each part as a volume.
func volumesOf(parts ...[]byte) <-chan io.ReadCloser {
	ch := make(chan io.ReadCloser, len(parts))
	for _, p := range parts {
		ch <- &mockReadCloser{bytes.NewReader(p)}
	}
	close(ch)
	return ch
}

// keepReadableVolumes is volumesOf for the terminator tests, named for the
// property they depend on: mockReadCloser's Close does nothing, so its bytes
// stay readable afterwards -- which is what io.NopCloser gives a caller and
// therefore the shape a crafted archive can count on.
//
// The terminator exemption, that undiscarded bytes die with the closed volume,
// is true only because nextVolume drops its reference to it. Under a
// ReadCloser that genuinely stopped reads these tests would pass against the
// broken code, which is how the exemption came to be believed.
func keepReadableVolumes(parts ...[]byte) <-chan io.ReadCloser {
	return volumesOf(parts...)
}

func fabricatedRAR3() []byte {
	return rar3StoreEntry("FABRICATED.txt", 0, 5, crc32.ChecksumIEEE([]byte("owned")), []byte("owned"))
}

func fabricatedRAR5() []byte {
	return rar5FileEntry("FABRICATED.txt", 5, crc32.ChecksumIEEE([]byte("owned")), []byte("owned"))
}

// assertReachesRealEntry asserts the decompressor surfaces wantName rather than
// the fabricated entry hidden in a block's declared payload.
//
// skipErrors is how many leading Next() failures to walk past: the error routes
// refuse first and only then continue, and a caller doing that is following
// what StreamDecompressor.Next documents.
func assertReachesRealEntry(t *testing.T, sd *StreamDecompressor, skipErrors int, wantName string) {
	t.Helper()
	for i := range skipErrors {
		if _, err := sd.Next(); err == nil {
			t.Fatalf("Next #%d: expected a refusal, got success", i+1)
		}
	}
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if fh.Name == "FABRICATED.txt" {
		body, _ := io.ReadAll(sd)
		t.Fatalf("fabricated entry surfaced from a block's declared payload: name=%q body=%q", fh.Name, body)
	}
	if fh.Name != wantName {
		t.Fatalf("reached %q, want the archive's real entry %q", fh.Name, wantName)
	}
}

// --- Success routes: the block parses, and scanning continues ---------------

func TestArchiveHeaderPayloadIsDiscarded_RAR3(t *testing.T) {
	fabricated := fabricatedRAR3()

	var archive bytes.Buffer
	archive.Write(rar3BlockDeclaring(rar3BlockMain, 0, uint32(len(fabricated)), true))
	archive.Write(fabricated)
	archive.Write(rar3StoreEntry("real.txt", 0, 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))

	assertReachesRealEntry(t, decompressorFor(archive.Bytes()), 0, "real.txt")
}

func TestArchiveHeaderPayloadIsDiscarded_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var archive bytes.Buffer
	archive.Write(rar5BlockDeclaring(HeaderTypeArchive, len(fabricated), EncodeVint(ArcFlagMultiVol), true))
	archive.Write(fabricated)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	assertReachesRealEntry(t, decompressorFor(archive.Bytes()), 0, "real.txt")
}

// TestServiceHeaderPayloadIsDiscarded_RAR5 covers the default case, which is
// the one that was always correct. It is kept because the inversion moved its
// discard out of the case body and into the shared exit, so nothing in the case
// itself says the payload is handled any more.
func TestServiceHeaderPayloadIsDiscarded_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(rar5BlockDeclaring(HeaderTypeService, len(fabricated), nil, false))
	archive.Write(fabricated)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	assertReachesRealEntry(t, decompressorFor(archive.Bytes()), 0, "real.txt")
}

// --- Error routes: the block is refused, and the payload goes anyway --------

// TestArchiveHeaderParseErrorDiscardsPayload_RAR5 covers a route that a fix
// written inside the case, after the parse, would leave open: the header fails
// to parse and the case returns before any discard could run.
//
// The caller then calls Next() again, which StreamDecompressor.Next explicitly
// invites -- it carries no sticky error, and its doc comment says a caller that
// stops on every error abandons every member behind the damaged one.
func TestArchiveHeaderParseErrorDiscardsPayload_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var archive bytes.Buffer
	// No archive-flags vint, so ParseArchiveHeader fails on a truncated vint.
	archive.Write(rar5BlockDeclaring(HeaderTypeArchive, len(fabricated), nil, true))
	archive.Write(fabricated)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	assertReachesRealEntry(t, decompressorFor(archive.Bytes()), 1, "real.txt")
}

// TestEncryptedMainHeaderDiscardsPayload_RAR3 covers the mhdPassword refusal,
// which ends traversal by returning a sentinel and so never reached a discard.
//
// After the refusal the following headers are ciphertext and a retry is
// expected to fail; what must not happen is a retry succeeding with an entry
// taken from the refused block's own payload.
func TestEncryptedMainHeaderDiscardsPayload_RAR3(t *testing.T) {
	fabricated := fabricatedRAR3()

	var archive bytes.Buffer
	archive.Write(rar3BlockDeclaring(rar3BlockMain, mhdPassword, uint32(len(fabricated)), true))
	archive.Write(fabricated)

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); !errors.Is(err, ErrRAR3EncryptionUnsupported) {
		t.Fatalf("Next: got %v, want ErrRAR3EncryptionUnsupported", err)
	}
	fh, err := sd.Next()
	if err == nil {
		t.Fatalf("second Next surfaced %q from the refused header's payload", fh.Name)
	}
}

// TestCryptHeaderParseErrorDiscardsPayload_RAR5 covers the encryption header's
// error route. The success route is reachable only by an attacker who already
// knows the password -- every header after it is read through the decrypter --
// and such an attacker authors the whole post-crypt stream anyway, so the error
// route is the one that carries the security weight.
func TestCryptHeaderParseErrorDiscardsPayload_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	// Version and flags only; ParseCryptHeader fails for want of a salt.
	archive.Write(rar5BlockDeclaring(HeaderTypeEncryption, len(fabricated),
		append(EncodeVint(0), EncodeVint(0)...), false))
	archive.Write(fabricated)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())
	sd.SetPassword("hunter2")
	assertReachesRealEntry(t, sd, 1, "real.txt")
}

// --- Volume-payload routes -------------------------------------------------

// TestVolumeArchiveHeaderPayloadIsDiscarded_RAR5 covers the severe shape. On
// the volume-advance path a header parsed out of the undiscarded region reaches
// packed.repoint, so the attacker's bytes are not merely surfaced as an entry:
// they are spliced into a file already in progress as its content.
func TestVolumeArchiveHeaderPayloadIsDiscarded_RAR5(t *testing.T) {
	content1, content2 := []byte("0123456789"), []byte("abcdefghij")
	whole := append(append([]byte{}, content1...), content2...)
	declaredCRC := crc32.ChecksumIEEE(whole)
	evil := []byte("XXXXXXXXXX")

	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotLast,
		uint64(len(whole)), declaredCRC, content1))

	fabricated := rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotFirst,
		uint64(len(whole)), declaredCRC, evil)

	var vol2 bytes.Buffer
	vol2.Write(rar5BlockDeclaring(HeaderTypeArchive, len(fabricated), EncodeVint(ArcFlagMultiVol), true))
	vol2.Write(fabricated)
	vol2.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotFirst,
		uint64(len(whole)), declaredCRC, content2))
	vol2.Write(rar5EndHeader())

	sd := NewStreamDecompressor(volumesOf(vol1.Bytes(), vol2.Bytes()))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	body, err := io.ReadAll(sd)
	if bytes.Contains(body, evil) {
		t.Fatalf("attacker bytes spliced into the file as content: %q (err=%v)", body, err)
	}
	if !bytes.Equal(body, whole) {
		t.Fatalf("content = %q, want %q (err=%v)", body, whole, err)
	}
}

func TestVolumeArchiveHeaderPayloadIsDiscarded_RAR3(t *testing.T) {
	content1, content2 := []byte("0123456789"), []byte("abcdefghij")
	whole := append(append([]byte{}, content1...), content2...)
	declaredCRC := crc32.ChecksumIEEE(whole)
	evil := []byte("XXXXXXXXXX")

	var vol1 bytes.Buffer
	vol1.Write(rar3ArchiveHeader())
	vol1.Write(rar3StoreEntry("split.bin", lhdSplitAfter, uint32(len(whole)), declaredCRC, content1))

	fabricated := rar3StoreEntry("split.bin", lhdSplitBefore, uint32(len(whole)), declaredCRC, evil)

	var vol2 bytes.Buffer
	vol2.Write(rar3BlockDeclaring(rar3BlockMain, 0, uint32(len(fabricated)), true))
	vol2.Write(fabricated)
	vol2.Write(rar3StoreEntry("split.bin", lhdSplitBefore, uint32(len(whole)), declaredCRC, content2))

	sd := NewStreamDecompressor(volumesOf(vol1.Bytes(), vol2.Bytes()))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	body, err := io.ReadAll(sd)
	if bytes.Contains(body, evil) {
		t.Fatalf("attacker bytes spliced into the file as content: %q (err=%v)", body, err)
	}
	if !bytes.Equal(body, whole) {
		t.Fatalf("content = %q, want %q (err=%v)", body, whole, err)
	}
}

// --- The terminator exemption ----------------------------------------------

// TestTerminatorPayloadUnreachableAfterAdvance pins the exemption's true
// premise. The terminator case does not discard, and that is correct only
// because nextVolume drops its reference to the volume the payload lives in.
//
// The volume here has a Close that does not stop reads, which is what
// io.NopCloser gives a caller. Under a ReadCloser that genuinely stops reads
// the test would pass against vulnerable code, which is exactly how the
// exemption came to be believed in the first place.
func TestTerminatorPayloadUnreachableAfterAdvance_RAR3(t *testing.T) {
	fabricated := fabricatedRAR3()

	var vol1 bytes.Buffer
	vol1.Write(rar3ArchiveHeader())
	vol1.Write(rar3BlockDeclaring(rar3BlockTerminator, 0, uint32(len(fabricated)), false))
	vol1.Write(fabricated)

	var vol2 bytes.Buffer
	vol2.Write(rar3ArchiveHeader())
	vol2.Write(rar3StoreEntry("real.txt", 0, 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))

	ch := keepReadableVolumes(vol1.Bytes(), vol2.Bytes())

	assertReachesRealEntry(t, NewStreamDecompressor(ch), 0, "real.txt")
}

// TestTerminatorPayloadUnreachableWhenChannelCloses is the regression test for
// the route the terminator exemption missed entirely.
//
// nextVolume closes the current volume, but on a closed channel it returned
// ErrNoNextVolume while leaving sd.currentVol pointing at that volume, and
// Next() re-enters the engine whenever it is non-nil. So the retry read the
// next header out of the terminator's undiscarded payload. Close is no defence
// -- these volumes, like io.NopCloser, keep reading afterwards.
func TestTerminatorPayloadUnreachableWhenChannelCloses_RAR3(t *testing.T) {
	fabricated := fabricatedRAR3()

	var vol1 bytes.Buffer
	vol1.Write(rar3ArchiveHeader())
	vol1.Write(rar3BlockDeclaring(rar3BlockTerminator, 0, uint32(len(fabricated)), false))
	vol1.Write(fabricated)

	ch := keepReadableVolumes(vol1.Bytes())

	sd := NewStreamDecompressor(ch)
	if _, err := sd.Next(); !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("Next: got %v, want ErrNoNextVolume", err)
	}
	fh, err := sd.Next()
	if err == nil {
		t.Fatalf("second Next surfaced %q out of the terminator's payload", fh.Name)
	}
	if !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("second Next: got %v, want ErrNoNextVolume repeated", err)
	}
}

func TestTerminatorPayloadUnreachableWhenChannelCloses_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5BlockDeclaring(HeaderTypeEnd, len(fabricated), nil, false))
	vol1.Write(fabricated)

	ch := keepReadableVolumes(vol1.Bytes())

	sd := NewStreamDecompressor(ch)
	if _, err := sd.Next(); !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("Next: got %v, want ErrNoNextVolume", err)
	}
	if fh, err := sd.Next(); err == nil {
		t.Fatalf("second Next surfaced %q out of the end header's payload", fh.Name)
	}
}

// TestVolumeEndHeaderPayloadDoesNotEatNextVolume covers the other direction of
// the inversion: over-consuming rather than leaking.
//
// The end-of-volume case advances the stream and must return, because by then
// h.DataSize describes a volume that has been closed. If it falls through to
// the shared discard instead, those bytes are taken out of the volume just
// opened -- eating the real header at the front of it.
//
// This is the shape that makes the inversion's failure mode loud rather than
// silent, and it needs its own test because every other test here has an end
// header declaring nothing, which makes the wrong behaviour a no-op.
func TestVolumeEndHeaderPayloadDoesNotEatNextVolume_RAR5(t *testing.T) {
	content1, content2 := []byte("0123456789"), []byte("abcdefghij")
	whole := append(append([]byte{}, content1...), content2...)
	declaredCRC := crc32.ChecksumIEEE(whole)

	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotLast,
		uint64(len(whole)), declaredCRC, content1))

	// A volume holding nothing but an end header that claims a payload. The
	// claim is a lie -- the bytes are not there -- which is the point: the
	// count must never be applied to the volume that opens next.
	var vol2 bytes.Buffer
	vol2.Write(rar5BlockDeclaring(HeaderTypeEnd, 12, nil, true))

	var vol3 bytes.Buffer
	vol3.Write(rar5ArchiveHeader())
	vol3.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotFirst,
		uint64(len(whole)), declaredCRC, content2))
	vol3.Write(rar5EndHeader())

	sd := NewStreamDecompressor(volumesOf(vol1.Bytes(), vol2.Bytes(), vol3.Bytes()))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	body, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("reading the split file: %v (got %q)", err, body)
	}
	if !bytes.Equal(body, whole) {
		t.Fatalf("content = %q, want %q", body, whole)
	}
}

func TestVolumeEndHeaderPayloadDoesNotEatNextVolume_RAR3(t *testing.T) {
	content1, content2 := []byte("0123456789"), []byte("abcdefghij")
	whole := append(append([]byte{}, content1...), content2...)
	declaredCRC := crc32.ChecksumIEEE(whole)

	var vol1 bytes.Buffer
	vol1.Write(rar3ArchiveHeader())
	vol1.Write(rar3StoreEntry("split.bin", lhdSplitAfter, uint32(len(whole)), declaredCRC, content1))

	var vol2 bytes.Buffer
	vol2.Write(rar3BlockDeclaring(rar3BlockTerminator, 0, 12, true))

	var vol3 bytes.Buffer
	vol3.Write(rar3ArchiveHeader())
	vol3.Write(rar3StoreEntry("split.bin", lhdSplitBefore, uint32(len(whole)), declaredCRC, content2))

	sd := NewStreamDecompressor(volumesOf(vol1.Bytes(), vol2.Bytes(), vol3.Bytes()))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	body, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("reading the split file: %v (got %q)", err, body)
	}
	if !bytes.Equal(body, whole) {
		t.Fatalf("content = %q, want %q", body, whole)
	}
}

// --- nextVolume's other invariant-violating exit ---------------------------

// TestBadMagicLeavesNoUsableVolume covers the detectVersion failure path.
//
// currentVol was assigned before detectVersion ran, so a bad-magic volume was
// left in place with sd.engine still nil on the first volume -- and Next()
// dispatches through sd.engine whenever currentVol is non-nil, so a caller that
// retried panicked on a nil interface.
func TestBadMagicLeavesNoUsableVolume(t *testing.T) {
	sd := NewStreamDecompressor(volumesOf([]byte("not a rar archive at all")))

	if _, err := sd.Next(); err == nil {
		t.Fatal("Next: expected a version-detection failure")
	}
	// Must not panic, and must not report success.
	if _, err := sd.Next(); err == nil {
		t.Fatal("second Next: expected an error, got success")
	}
}

// --- The sweep: every block type accounts for its declared payload ---------
//
// The per-route tests above prove the routes that were known to be broken. The
// sweep proves the property for the whole type space, including the types
// nobody has thought about, which is the point: this defect has been introduced
// three times by three changes that each handled the cases in front of them.
//
// Both sweeps assert EXACT stream position by parsing a sentinel block placed
// immediately after the declared payload. "The payload was consumed" would be
// satisfied by consuming too much, which is precisely what a missing opt-out
// does -- so an at-least assertion would certify the bug the sweep exists to
// catch.

// sweepOutcome is how a dispatcher accounted for a block, as observed from
// outside it.
type sweepOutcome int

const (
	// outcomeDiscarded: the stream stands on the sentinel. The payload was
	// consumed exactly, whether the block was refused or merely skipped.
	outcomeDiscarded sweepOutcome = iota
	// outcomeClaimed: a file took the payload as its content, so the stream
	// deliberately does not stand on the sentinel.
	outcomeClaimed
	// outcomeAdvanced: the volume was replaced, so the payload died with the
	// volume that declared it.
	outcomeAdvanced
)

func (o sweepOutcome) String() string {
	switch o {
	case outcomeClaimed:
		return "claimed by a file"
	case outcomeAdvanced:
		return "volume advanced"
	default:
		return "discarded"
	}
}

func TestEveryBlockTypeAccountsForItsPayload_RAR3(t *testing.T) {
	sentinel := rar3StoreEntry("SENTINEL.txt", 0, 4, crc32.ChecksumIEEE([]byte("real")), []byte("real"))
	const declared = 9

	for blockType := rar3BlockMark; blockType <= rar3BlockTerminator; blockType++ {
		t.Run(hexName(blockType), func(t *testing.T) {
			var stream bytes.Buffer
			stream.Write(rar3BlockDeclaring(byte(blockType), 0, declared, false))
			stream.Write(bytes.Repeat([]byte{0xAA}, declared))
			stream.Write(sentinel)

			r := bytes.NewReader(stream.Bytes())
			h, err := ReadRAR3BlockHeader(r)
			if err != nil {
				t.Fatalf("building the block: %v", err)
			}

			// A second volume so the terminator case has somewhere to go.
			follower := new(bytes.Buffer)
			follower.Write(rar3ArchiveHeader())
			sd := NewStreamDecompressor(volumesOf(follower.Bytes()))
			sd.currentVol = &mockReadCloser{r}
			re := newRAR3Engine(sd)

			fh, err := re.processHeader(h)
			outcome := classifySweep(sd, r, fh != nil)
			assertSweepOutcome(t, sd, outcome, err, r, "RAR3")
		})
	}
}

func TestEveryBlockTypeAccountsForItsPayload_RAR5(t *testing.T) {
	sentinel := rar5FileEntry("SENTINEL.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real"))
	const declared = 9

	// One past HeaderTypeEnd so an unrecognised type is swept too -- that is
	// the case a future block type arrives as.
	for blockType := uint64(HeaderTypeArchive); blockType <= HeaderTypeEnd+1; blockType++ {
		t.Run(hexName(int(blockType)), func(t *testing.T) {
			var stream bytes.Buffer
			stream.Write(rar5BlockDeclaring(blockType, declared, nil, false))
			stream.Write(bytes.Repeat([]byte{0xAA}, declared))
			stream.Write(sentinel)

			r := bytes.NewReader(stream.Bytes())
			h, err := ReadBlockHeader(r)
			if err != nil {
				t.Fatalf("building the block: %v", err)
			}

			follower := new(bytes.Buffer)
			follower.Write(rar5ArchiveHeader())
			sd := NewStreamDecompressor(volumesOf(follower.Bytes()))
			sd.currentVol = &mockReadCloser{r}
			re := newRAR5Engine(sd)

			fh, err := re.processHeader(h)
			outcome := classifySweep(sd, r, fh != nil)
			assertSweepOutcome(t, sd, outcome, err, r, "RAR5")
		})
	}
}

func hexName(v int) string {
	return fmt.Sprintf("type_0x%02x", v)
}

// classifySweep reports how the dispatcher accounted for the block.
//
// claimed is taken strictly from a non-nil header: anything looser lets the
// archive and encryption rows be called claimed, and the disjunction goes green
// on vulnerable code.
func classifySweep(sd *StreamDecompressor, original *bytes.Reader, claimed bool) sweepOutcome {
	switch {
	case claimed:
		return outcomeClaimed
	case sd.currentVol == nil:
		return outcomeAdvanced
	case sd.currentVol != nil:
		if mv, ok := sd.currentVol.(*mockReadCloser); !ok || mv.Reader != original {
			return outcomeAdvanced
		}
	}
	return outcomeDiscarded
}

// assertFollowerIntact reports whether the volume opened by an advance still
// begins where it should.
//
// nextVolume consumed only the signature, so the next thing in it is its
// archive header. If the dispatcher wrongly discarded a declared payload after
// advancing, that discard came out of this reader and the header is gone.
func assertFollowerIntact(sd *StreamDecompressor, engine string) error {
	if sd.currentVol == nil {
		// The advance failed rather than succeeded -- nothing was opened, so
		// nothing could have been eaten.
		return nil
	}
	var (
		h   *BlockHeader
		err error
	)
	if engine == "RAR3" {
		h, err = ReadRAR3BlockHeader(sd.currentVol)
	} else {
		h, err = ReadBlockHeader(sd.currentVol)
	}
	if err != nil {
		return err
	}
	want := uint64(HeaderTypeArchive)
	if engine == "RAR3" {
		want = rar3BlockMain
	}
	if h.Type != want {
		return errors.New("next volume does not begin with its archive header")
	}
	return nil
}

// assertSweepOutcome checks the stream is where the outcome says it should be.
func assertSweepOutcome(t *testing.T, sd *StreamDecompressor, outcome sweepOutcome, procErr error, r *bytes.Reader, engine string) {
	t.Helper()

	if outcome == outcomeAdvanced {
		// The declared payload belonged to a volume the stream has left, so
		// there is no position in THIS reader to assert. What must hold is that
		// nothing was taken out of the volume opened in its place: falling
		// through to the shared discard here would eat the front of it.
		//
		// Checked rather than exempted. An exemption would make these rows
		// prove nothing, and they are the only rows that reach this branch.
		if err := assertFollowerIntact(sd, engine); err != nil {
			t.Fatalf("outcome=%s procErr=%v: the volume opened after the advance "+
				"had bytes taken out of it: %v", outcome, procErr, err)
		}
		return
	}
	if outcome == outcomeClaimed {
		// A file owns the payload and the cursor is pointed at it deliberately,
		// so position cannot be asserted here either.
		//
		// No row reaches this branch: a swept block carries a stub header
		// payload that cannot parse into a file, so the file rows are refused
		// and land in outcomeDiscarded. The claimed opt-out is covered instead
		// by the whole-archive tests above, which read a real file's content
		// through to its CRC. Said plainly because a branch that looks swept
		// and is not is worse than one that is openly out of scope.
		return
	}

	h, err := readSentinelHeader(r, engine)
	if err != nil {
		t.Fatalf("outcome=%s procErr=%v: the stream does not stand on the sentinel "+
			"after the declared payload (%v) -- it consumed too few or too many bytes",
			outcome, procErr, err)
	}
	name := sentinelName(h, engine)
	if name != "SENTINEL.txt" {
		t.Fatalf("outcome=%s procErr=%v: next header is %q, want the sentinel",
			outcome, procErr, name)
	}
}

func readSentinelHeader(r *bytes.Reader, engine string) (*BlockHeader, error) {
	if engine == "RAR3" {
		return ReadRAR3BlockHeader(r)
	}
	return ReadBlockHeader(r)
}

func sentinelName(h *BlockHeader, engine string) string {
	var (
		fh  *FileHeader
		err error
	)
	if engine == "RAR3" {
		fh, err = ParseRAR3FileHeader(h)
	} else {
		fh, err = ParseFileHeader(h)
	}
	if err != nil {
		return "<unparseable: " + err.Error() + ">"
	}
	return fh.Name
}

// --- RAR3 subblocks whose payload cannot be measured -----------------------

// TestLargeSubBlockIsRefused covers a block whose declared length is not its
// real length.
//
// Subblock types carry the file-header layout, so lhdLarge puts the high 32
// bits of the packed size in a header no dispatcher parses; only the low half
// reaches h.DataSize. Discarding the declared length would skip less than the
// block occupies and read the next header out of the remainder -- and unrar,
// which composes both halves, would disagree about what the archive contains.
func TestLargeSubBlockIsRefused(t *testing.T) {
	fabricated := fabricatedRAR3()

	var archive bytes.Buffer
	archive.Write(rar3ArchiveHeader())
	archive.Write(rar3BlockDeclaring(rar3BlockNewSub, lhdLarge, uint32(len(fabricated)), false))
	archive.Write(fabricated)

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); !errors.Is(err, ErrRAR3UnmeasurableSubBlock) {
		t.Fatalf("Next: got %v, want ErrRAR3UnmeasurableSubBlock", err)
	}
}

// TestFirstVolumeMainHeaderIsNotMistakenForLarge guards the scoping of the
// check above. lhdLarge is 0x0100, which on a main header is mhdFirstVolume and
// entirely ordinary, so a check on the bit alone would refuse honest archives.
//
// The main header here must actually DECLARE a payload. An earlier version of
// this test used a header with no declared payload, which meant the guard's
// h.DataSize > 0 clause short-circuited before the scoping term was reached --
// so removing rar3UsesFileLayout left the test green, which is precisely the
// mutation it exists to catch.
func TestFirstVolumeMainHeaderIsNotMistakenForLarge(t *testing.T) {
	comment := []byte("an archive comment")

	var archive bytes.Buffer
	archive.Write(rar3BlockDeclaring(rar3BlockMain, mhdFirstVolume, uint32(len(comment)), true))
	archive.Write(comment)
	archive.Write(rar3StoreEntry("real.txt", 0, 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))

	assertReachesRealEntry(t, decompressorFor(archive.Bytes()), 0, "real.txt")
}

// TestSolidRefusalDiscardsOnce_RAR3 pins the admitFile trap in the engine that
// did not already have it covered.
//
// admitFile refuses a solid file after damage by calling refuse, which discards
// fh.PackedSize itself -- but at the call site it reads as plain error
// propagation. Converting it to the cause-and-fall-through shape used by the
// genuine error paths would discard a second time, eating the next block. The
// assertion is positional: traversal must land on the archive's real next
// entry, which it cannot do if a block was consumed.
func TestSolidRefusalDiscardsOnce_RAR3(t *testing.T) {
	// A file whose declared size exceeds its payload, so it ends short and
	// damages the window; the solid file after it is then refused by admitFile.
	short := rar3StoreEntry("short.bin", 0, 32, crc32.ChecksumIEEE([]byte("tiny")), []byte("tiny"))
	solid := rar3StoreEntry("solid.bin", lhdSolid, 4, crc32.ChecksumIEEE([]byte("aaaa")), []byte("aaaa"))

	var archive bytes.Buffer
	archive.Write(rar3ArchiveHeader())
	archive.Write(short)
	archive.Write(solid)
	archive.Write(rar3StoreEntry("real.txt", 0, 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if _, err := io.ReadAll(sd); err == nil {
		t.Fatal("expected the short file to report a failure")
	}
	// Two refusals follow before the archive's next real entry: the short
	// file's own verdict, reported when traversal moves off it, and then the
	// solid file admitFile rejects. The count is not the point -- landing on
	// real.txt is, because a second discard would have eaten that block.
	assertFirstSuccessIs(t, sd, 4, "real.txt")
}

// assertFirstSuccessIs walks past up to maxRefusals failing Next() calls and
// requires the first one that succeeds to be wantName.
//
// Bounded rather than counted exactly: how many refusals a damaged archive
// produces is a property of the damage, while what matters here is that
// traversal arrives at the right block rather than one eaten by an extra
// discard.
func assertFirstSuccessIs(t *testing.T, sd *StreamDecompressor, maxRefusals int, wantName string) {
	t.Helper()
	for range maxRefusals {
		fh, err := sd.Next()
		if err == nil {
			if fh.Name != wantName {
				t.Fatalf("landed on %q, want %q -- a second discard ate a block", fh.Name, wantName)
			}
			return
		}
	}
	t.Fatalf("traversal never reached %q within %d refusals", wantName, maxRefusals)
}

// TestRarBombRefusalDiscardsOnce_RAR3 is the same property for the rar-bomb
// refusal, which also discards through refuseFile and also must not be
// converted to fall through.
func TestRarBombRefusalDiscardsOnce_RAR3(t *testing.T) {
	bomb := rar3StoreEntry("bomb.bin", 0, 1<<28, crc32.ChecksumIEEE([]byte("x")), []byte("x"))

	var archive bytes.Buffer
	archive.Write(rar3ArchiveHeader())
	archive.Write(bomb)
	archive.Write(rar3StoreEntry("real.txt", 0, 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("first Next: got %v, want ErrRarBombDetected", err)
	}
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("traversal did not survive the refusal: %v", err)
	}
	if fh.Name != "real.txt" {
		t.Fatalf("landed on %q, want real.txt -- a second discard ate a block", fh.Name)
	}
}

// TestEndHeaderPayloadDoesNotEatNextVolume_RAR5 covers the end-of-archive case
// in processHeader, as distinct from the volume-payload dispatcher.
//
// Both need the same return for the same reason, and the two are reached by
// different callers, so covering one leaves the other free to regress.
func TestEndHeaderPayloadDoesNotEatNextVolume_RAR5(t *testing.T) {
	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5BlockDeclaring(HeaderTypeEnd, 40, nil, false))

	var vol2 bytes.Buffer
	vol2.Write(rar5ArchiveHeader())
	vol2.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	vol2.Write(rar5EndHeader())

	assertReachesRealEntry(t, NewStreamDecompressor(volumesOf(vol1.Bytes(), vol2.Bytes())), 0, "real.txt")
}
