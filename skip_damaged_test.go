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

// damageFirstFile runs a decompressor up to the point where the leading short
// file has failed and been reported, and returns it positioned to continue.
//
// The four tests below all need that same five-step preamble; sharing it keeps
// a change to how damage is produced or asserted from having to be made four
// times. It asserts rather than assumes each step, so a fixture that stops
// producing a damaged file fails here instead of silently making the caller's
// own assertion vacuous.
func damageFirstFile(t *testing.T, archive []byte) (*StreamDecompressor, error) {
	t.Helper()

	sd := decompressorFor(archive)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if fh.Name != "truncated.bin" {
		t.Fatalf("first entry is %q; the fixture is not the shape these tests need", fh.Name)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the damaged file returned %v; want ErrTruncatedFile", err)
	}
	_, err = sd.Next()
	if err == nil {
		t.Fatal("the damaged file was not reported by Next")
	}
	return sd, err
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

	sd, err := damageFirstFile(t, archive.Bytes())

	// Next reports the failure rather than the following header.
	fe, ok := errors.AsType[*FileError](err)
	if !ok {
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

	sd, _ := damageFirstFile(t, archive.Bytes())

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

	sd, _ := damageFirstFile(t, archive.Bytes())

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

	sd, _ := damageFirstFile(t, damagedArchive.Bytes())
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

// alwaysFailsAfter serves data and then fails with the same non-EOF error on
// every subsequent call.
//
// errAfterBytes reports io.EOF after its one failure, which makes io.Copy in
// packedCursor.drain stop cleanly -- so a test built on it exercises the
// short-drain branch, not the failed-drain branch. Distinguishing the two is
// the whole point here.
type alwaysFailsAfter struct {
	data   []byte
	off    int
	failAt int
	err    error
}

func (a *alwaysFailsAfter) Read(p []byte) (int, error) {
	if a.off >= a.failAt {
		return 0, a.err
	}
	n := min(len(p), a.failAt-a.off)
	copy(p, a.data[a.off:a.off+n])
	a.off += n
	return n, nil
}

// TestSkipDamagedFile_ShortDrainIsNotContinuable covers a truncated volume:
// the promised payload is simply not on the media, so the drain stops early.
//
// The stream is then wherever the media ran out, which the block structure
// does not describe, so no continuation is offered. The window is still
// incomplete though, and that must be recorded -- the file wrote fewer bytes
// than it declared whatever the reason.
func TestSkipDamagedFile_ShortDrainIsNotContinuable(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	full := archive.Bytes()

	sd := decompressorFor(full[:len(full)-4])
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	_, _ = io.Copy(io.Discard, sd)

	_, err := sd.Next()
	// Checked before the type assertion: AsType also reports false for a nil
	// error, so without this a regression where Next simply succeeds -- the
	// worse outcome, since it surfaces whatever the stream is sitting on --
	// would satisfy the assertion below.
	if err == nil {
		t.Fatal("Next reported success after a short drain; the stream is " +
			"wherever the media ran out, so there is nothing safe to return")
	}
	if _, ok := errors.AsType[*FileError](err); ok {
		t.Fatalf("a short drain was offered as continuable (%v); the stream is "+
			"wherever the media ran out, not on a block header", err)
	}
	if !sd.damaged {
		t.Error("a file that delivered less than it declared was not recorded " +
			"as damaging the window; a solid successor would then decode " +
			"against history that was never written")
	}
}

// TestSkipDamagedFile_FailedDrainIsNotContinuable covers the other unsettled
// case: the drain itself errors, so the offset is unknown rather than merely
// past the end of the media.
func TestSkipDamagedFile_FailedDrainIsNotContinuable(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	full := archive.Bytes()

	readErr := errors.New("media failed mid-payload")
	src := &alwaysFailsAfter{data: full, failAt: len(full) - 4, err: readErr}

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
	// Asserted, not assumed: without this the test could pass through the
	// short-drain branch and never exercise a failing drain at all.
	if !errors.Is(err, readErr) {
		t.Fatalf("got %v; the drain did not fail, so this test is not "+
			"exercising the branch it names", err)
	}
	if _, ok := errors.AsType[*FileError](err); ok {
		t.Fatalf("a failed drain was offered as continuable (%v); the stream "+
			"offset is unknown, so reading on risks parsing a header out of "+
			"payload", err)
	}
}

// TestSkipDamagedFile_SolidRefusedAcrossVolumeAfterTruncation is the
// regression test for the case damage tracking originally missed.
//
// A truncated volume takes the short-drain path, which produces no FileError.
// While damage was recorded from the FileError rather than from the file
// ending short, this left damaged clear -- and a solid file opening the NEXT
// volume was admitted, decoding against a window its predecessor never
// finished writing. That is the ordinary Usenet shape: one segment lost, the
// remaining volumes intact.
func TestSkipDamagedFile_SolidRefusedAcrossVolumeAfterTruncation(t *testing.T) {
	// Volume 1: a file declaring far more payload than the media carries.
	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5FileEntry("truncated.bin", 1000, 0xdeadbeef, make([]byte, 1000)))
	truncated := vol1.Bytes()[:vol1.Len()-990]

	// Volume 2: intact, opening with a solid entry that back-references the
	// history volume 1 failed to write.
	content := []byte("solid content depending on history")
	var vol2 bytes.Buffer
	vol2.Write(rar5ArchiveHeader())
	vol2.Write(rar5EntryComp("solid.bin", FileCompSolid, uint64(len(content)),
		crc32.ChecksumIEEE(content), content))
	vol2.Write(rar5EndHeader())

	volumes := make(chan io.ReadCloser, 2)
	volumes <- &mockReadCloser{bytes.NewReader(truncated)}
	volumes <- &mockReadCloser{bytes.NewReader(vol2.Bytes())}
	close(volumes)
	sd := NewStreamDecompressor(volumes)

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if fh.Name != "truncated.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", fh.Name)
	}
	n, err := io.Copy(io.Discard, sd)
	if err == nil {
		t.Fatal("the truncated file reported success")
	}
	// Guards the fixture: if the file somehow delivered everything it
	// declared, there is no damage and the assertion below proves nothing.
	if n >= 1000 {
		t.Fatalf("the file delivered %d of 1000 bytes, so it is not truncated", n)
	}

	// The first Next reports the truncation. Nothing in the library stops the
	// caller from calling again -- there is no sticky terminal state on
	// StreamDecompressor -- so the second advances to volume 2. That is the
	// call the damage state has to survive to.
	if _, err = sd.Next(); err == nil {
		t.Fatal("the truncation was not reported")
	}
	if !sd.damaged {
		t.Fatal("a truncated file was not recorded as damaging the window, so " +
			"the guard below cannot fire for the right reason")
	}

	_, err = sd.Next()
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("a solid file opening the next volume after a truncated one "+
			"returned %v; want ErrSolidStreamBroken. Its back-references reach "+
			"into %d bytes that were never written", err, 1000-n)
	}
}

// TestSkipDamagedFile_AbandonedCursorIsNotContinuable is the regression test
// for the fabrication this type nearly enabled.
//
// packedCursor.invalidate zeroes the count without reading, and the
// volume-advance path invalidates BEFORE it discovers whether a next volume
// exists. So every failure there -- a header that fails its CRC, a refused
// header, a channel that closed -- reaches endFile with the count at zero and
// the file short. While continuation was gated on owed() == 0, that looked
// exactly like a completed drain, and the caller was told it could resume from
// a position no drain had established.
//
// A crafted archive turns that into a fabricated entry: the bytes that fail
// the header CRC also decide how far ReadBlockHeader consumed before giving
// up, so the archive chooses the offset the next header is parsed from --
// including inside a preceding file's payload. CLAUDE.md names that class as
// the one this library must never allow.
func TestSkipDamagedFile_AbandonedCursorIsNotContinuable(t *testing.T) {
	// Volume 1: a file whose payload continues into the next volume.
	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5SplitEntry("a.bin", 500, []byte("ten bytes!")))

	// Volume 2: a header that parses far enough to consume bytes and then
	// fails its CRC, followed by an entry the archive would like surfaced.
	pwned := []byte("ATTACKER CONTROLLED BYTES")
	var vol2 bytes.Buffer
	vol2.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	vol2.Write([]byte{0xff, 0xff, 0xff, 0xff, 0x80, 0x80, 0x02, 0x00})
	vol2.Write(goodEntry("PWNED.bin", pwned))
	vol2.Write(rar5EndHeader())

	volumes := make(chan io.ReadCloser, 2)
	volumes <- &mockReadCloser{bytes.NewReader(vol1.Bytes())}
	volumes <- &mockReadCloser{bytes.NewReader(vol2.Bytes())}
	close(volumes)
	sd := NewStreamDecompressor(volumes)

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if fh.Name != "a.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", fh.Name)
	}
	_, _ = io.Copy(io.Discard, sd)

	fh, err = sd.Next()
	// A nil error here is the worst outcome, not a passing one: it means Next
	// surfaced whatever the failed advance left the stream pointing at. AsType
	// reports false for nil, so this has to be rejected first.
	if err == nil {
		t.Fatalf("Next reported success after a failed volume advance and "+
			"returned %q; the offset it parsed that from was chosen by the "+
			"archive", fh.Name)
	}
	if fh != nil && fh.Name == "PWNED.bin" {
		t.Fatalf("Next surfaced the entry planted after the CRC-failing "+
			"header: %q", fh.Name)
	}
	if fe, ok := errors.AsType[*FileError](err); ok {
		t.Fatalf("a file whose cursor was abandoned on a failed volume advance "+
			"was offered as continuable (%v, header %v). No drain established "+
			"that position, so resuming parses a header from an offset the "+
			"archive chose", err, fe.Header)
	}
}

// rar5SplitEntry emits a file block marked as continuing into the next volume,
// so reading it drives the multi-volume advance path.
func rar5SplitEntry(name string, unpackedSize uint64, payload []byte) []byte {
	var fp bytes.Buffer
	fp.Write(EncodeVint(FileFlagHasCRC32))
	fp.Write(EncodeVint(unpackedSize))
	fp.Write(EncodeVint(0))
	fp.Write([]byte{0, 0, 0, 0})
	fp.Write(EncodeVint(0))
	fp.Write(EncodeVint(1))
	fp.Write(EncodeVint(uint64(len(name))))
	fp.WriteString(name)

	var hp bytes.Buffer
	hp.Write(EncodeVint(HeaderTypeFile))
	// HasData + DataNotLast: the payload continues in the next volume.
	hp.Write(EncodeVint(HeaderFlagHasData | HeaderFlagDataNotLast))
	hp.Write(EncodeVint(uint64(len(payload))))
	hp.Write(fp.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(hp.Bytes()))
	out.Write(payload)
	return out.Bytes()
}

// TestSkipDamagedFile_SolidRefusalDropsPayload pins that ErrSolidStreamBroken
// obeys the rule every other refusal in this package obeys.
//
// CLAUDE.md: "Refusing a file means dropping its payload, whatever the reason
// for the refusal ... Do not narrow it to particular errors." A refused block
// that keeps its payload supplies the next entry, because traversal continues
// afterwards -- the caller gets the error and calls Next again. This refusal
// reason is newer than that rule, and asserting the error alone would not have
// noticed: replacing the refuse() call with a bare return leaves every other
// test in this file passing while a crafted archive gets a fabricated entry.
func TestSkipDamagedFile_SolidRefusalDropsPayload(t *testing.T) {
	// The solid file's payload is itself a well-formed entry. If the refusal
	// leaves those bytes in the stream, the next header is parsed out of them.
	pwned := []byte("ATTACKER CONTROLLED BYTES")
	smuggled := goodEntry("PWNED.bin", pwned)

	tail := []byte("the real next file")
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid,
		uint64(len(smuggled)), 0x1234, smuggled))
	archive.Write(goodEntry("legit.bin", tail))
	archive.Write(rar5EndHeader())

	sd, _ := damageFirstFile(t, archive.Bytes())

	if _, err := sd.Next(); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("the solid file was not refused (%v); this test cannot check "+
			"what a refusal drops if nothing was refused", err)
	}

	// Traversal continues, so whatever the refusal left behind is what gets
	// parsed next.
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next after a refusal returned %v; the refused payload should "+
			"have been dropped, leaving the stream on the next real header", err)
	}
	if fh.Name == "PWNED.bin" {
		t.Fatalf("the refused file's payload supplied the next entry: got %q. "+
			"ErrSolidStreamBroken must drop the payload like every other "+
			"refusal, or it becomes a header-fabrication route", fh.Name)
	}
	if fh.Name != "legit.bin" {
		t.Fatalf("reached %q; want legit.bin", fh.Name)
	}
	got, err := io.ReadAll(sd)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading the file after a refusal: %v", err)
	}
	if !bytes.Equal(got, tail) {
		t.Errorf("the file after a refusal decoded to %q; want %q", got, tail)
	}
}

// TestRAR3_SolidRefusalAfterDamage covers admitFile in the RAR3 engine, which
// had no coverage at all -- the guard was added to both engines but only
// exercised in one, and this codebase's two engines have repeatedly diverged.
func TestRAR3_SolidRefusalAfterDamage(t *testing.T) {
	const solidFlag = 0x0010 // LHD_SOLID

	var archive bytes.Buffer
	archive.Write(rar3ArchiveHeader())
	// Declares 100 unpacked bytes but carries 10: ends short.
	archive.Write(rar3StoreEntry("truncated.bin", 0, 100, 0xdeadbeef,
		[]byte("only ten!!")))
	archive.Write(rar3StoreEntry("solid.bin", solidFlag, 20, 0x1234,
		[]byte("twenty bytes exactly")))

	sd := decompressorFor(archive.Bytes())
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if fh.Name != "truncated.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", fh.Name)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the damaged file returned %v; want ErrTruncatedFile", err)
	}
	if _, err := sd.Next(); err == nil {
		t.Fatal("the damaged file was not reported")
	}

	_, err = sd.Next()
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("a RAR3 solid file after a damaged one returned %v; want "+
			"ErrSolidStreamBroken. The guard exists in both engines and must "+
			"fire in both", err)
	}
}

// badCRCEntry carries its full declared length but records a checksum the
// content does not match: damage by wrong bytes rather than missing ones.
func badCRCEntry(name string, content []byte) []byte {
	wrong := crc32.ChecksumIEEE(content) ^ 0xffffffff
	return rar5FileEntry(name, uint64(len(content)), wrong, content)
}

// TestSkipDamagedFile_ChecksumFailureIsContinuable covers the commonest damage
// signal in the workload this feature targets.
//
// A file that reached its declared size and then failed its CRC32 is just as
// skippable as a truncated one: the cursor is drained and the stream is on the
// next header. Requiring the file to have ended short left this case reported
// as a bare error indistinguishable from end-of-archive -- and asymmetrically
// so, since reading the same file to EOF surfaces the mismatch during Read and
// then returns cleanly from Next.
func TestSkipDamagedFile_ChecksumFailureIsContinuable(t *testing.T) {
	tail := []byte("an entirely intact second file")

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(badCRCEntry("bad.bin", []byte("content whose CRC will not match")))
	archive.Write(goodEntry("good.bin", tail))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if fh.Name != "bad.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", fh.Name)
	}

	// Skipped, not read: the mismatch is found by the teardown drain.
	_, err = sd.Next()
	fe, ok := errors.AsType[*FileError](err)
	if !ok {
		t.Fatalf("skipping a CRC-mismatched file returned %v (%T); want a "+
			"*FileError. The stream is on the next header, so the caller has "+
			"no way to learn it may continue", err, err)
	}
	if !errors.Is(err, ErrCRCMismatch) {
		t.Errorf("the wrapper hid the cause: %v", err)
	}
	if fe.Header == nil || fe.Header.Name != "bad.bin" {
		t.Errorf("FileError names %v; want bad.bin", fe.Header)
	}

	fh, err = sd.Next()
	if err != nil {
		t.Fatalf("Next after the FileError returned %v; it promised the "+
			"traversal could continue", err)
	}
	if fh.Name != "good.bin" {
		t.Fatalf("continued to %q; want good.bin", fh.Name)
	}
}

// TestSkipDamagedFile_ChecksumFailureDamagesWindow pins the other half. A file
// whose CRC32 did not match wrote the WRONG bytes into the shared history, so
// a solid successor decodes against content the archive never assumed --
// silently, since nothing in the format marks it. Keying damage on "ended
// short" alone admitted exactly this.
func TestSkipDamagedFile_ChecksumFailureDamagesWindow(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(badCRCEntry("bad.bin", []byte("content whose CRC will not match")))
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234,
		[]byte("twenty bytes exactly")))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if _, err := io.Copy(io.Discard, sd); !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("reading bad.bin returned %v; want ErrCRCMismatch, or this "+
			"test is not exercising a checksum failure", err)
	}
	// No second report from Next: the mismatch was already delivered during
	// Read, and repeating it would make one corrupt file an archive nobody can
	// read past. So this call goes straight on to the solid successor.
	_, err := sd.Next()
	if !sd.damaged {
		t.Fatal("a CRC-mismatched file was not recorded as damaging the window")
	}
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("a solid file after a CRC-mismatched one returned %v; want "+
			"ErrSolidStreamBroken. Its back-references reach into bytes known "+
			"to be wrong", err)
	}
}

// TestSkipDamagedFile_RefusedFileDamagesWindow covers a file that never
// decoded at all.
//
// A refusal drops the payload and returns before fileReader.begin, so the file
// never becomes active and finishCurrentFile never sees it. Its output is
// nonetheless absent from the shared window, and a solid successor's
// back-references assume it is there. Window.CopyBytes bounds distances by the
// history actually written, but the shortfall here sits INSIDE that bound --
// the successor reads an earlier file's bytes rather than reading past the
// end -- so nothing catches it and the output is silently wrong.
func TestSkipDamagedFile_RefusedFileDamagesWindow(t *testing.T) {
	// A rar bomb: declared unpacked size far exceeds both 1 MiB and 1000x the
	// packed size, so processHeader refuses it before any decoding.
	bomb := rar5FileEntry("bomb.bin", 2*1024*1024, 0x1234, []byte("ten bytes!"))

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(bomb)
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234,
		[]byte("twenty bytes exactly")))
	archive.Write(rar5EndHeader())

	sd := decompressorFor(archive.Bytes())

	_, err := sd.Next()
	if !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("the first entry returned %v; want ErrRarBombDetected, or "+
			"this test is not exercising a refusal", err)
	}
	if !sd.damaged {
		t.Error("a refused file was not recorded as damaging the window; its " +
			"output never reached the window, so a solid successor's " +
			"back-references land on an earlier file's bytes")
	}

	_, err = sd.Next()
	if !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("a solid file after a refused one returned %v; want "+
			"ErrSolidStreamBroken. The refused file contributed nothing to "+
			"the window it back-references", err)
	}
}
