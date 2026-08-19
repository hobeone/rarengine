package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// fixtureBytes loads an on-disk archive. These are unrar-produced, so a
// truncation test against them exercises real header layouts rather than the
// hand-built ones the in-memory builders produce.
func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// multiVolumeChan feeds the ten rar5_multi parts in order. trimFirst, when
// non-negative, cuts that many bytes off the end of part01 so the file's
// payload runs short there and the reader has to advance mid-file.
func multiVolumeChan(t *testing.T, trimFirst int) <-chan io.ReadCloser {
	t.Helper()

	names := make([]string, 0, 10)
	for i := 1; i <= 9; i++ {
		names = append(names, fmt.Sprintf("rar5_multi.part0%d.rar", i))
	}
	names = append(names, "rar5_multi.part10.rar")

	volumes := make(chan io.ReadCloser, len(names))
	for i, name := range names {
		b := fixtureBytes(t, name)
		if i == 0 && trimFirst >= 0 {
			if trimFirst >= len(b) {
				t.Fatalf("trim %d exceeds part01 length %d", trimFirst, len(b))
			}
			b = b[:len(b)-trimFirst]
		}
		volumes <- &mockReadCloser{bytes.NewReader(b)}
	}
	close(volumes)
	return volumes
}

func decompressorFor(data []byte) *StreamDecompressor {
	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(data)}
	close(volumes)
	return NewStreamDecompressor(volumes)
}

// TestFileReader_TruncationIsReported is the #21 reproduction. A stream that
// ends mid-payload used to be handed to the caller as a short read plus a
// clean io.EOF, which io.Copy reports as success -- so UnpackDir wrote the
// short file and logged it as complete.
//
// The cut offsets are relative to each fixture's length and land inside the
// payload rather than the header. If a regenerated fixture moves them into
// the header, Next() fails instead and the subtest says so rather than
// silently testing nothing.
func TestFileReader_TruncationIsReported(t *testing.T) {
	cases := []struct {
		name    string
		archive func(t *testing.T) []byte
		// trim is how many bytes to drop from the end.
		trim int
	}{
		{
			name:    "rar5 store, payload partly present",
			archive: func(t *testing.T) []byte { return fixtureBytes(t, "rar5_store.rar") },
			trim:    10,
		},
		{
			name:    "rar5 store, payload entirely absent",
			archive: func(t *testing.T) []byte { return fixtureBytes(t, "rar5_store.rar") },
			trim:    23,
		},
		{
			name:    "rar5 compressed",
			archive: func(t *testing.T) []byte { return fixtureBytes(t, "rar5_compress.rar") },
			trim:    79,
		},
		{
			name: "rar3 store",
			archive: func(t *testing.T) []byte {
				return makeRAR3StoreArchive("hello.txt", []byte("hello rar3 world"))
			},
			trim: 5,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full := tc.archive(t)
			if tc.trim >= len(full) {
				t.Fatalf("trim %d exceeds archive length %d", tc.trim, len(full))
			}
			sd := decompressorFor(full[:len(full)-tc.trim])

			fh, err := sd.Next()
			if err != nil {
				t.Fatalf("Next() failed, so the cut landed in the header rather than the payload "+
					"and this case tests nothing: %v", err)
			}

			got, err := io.ReadAll(sd)
			if !errors.Is(err, ErrTruncatedFile) {
				t.Fatalf("truncated %q read %d of %d declared bytes and returned err=%v; want ErrTruncatedFile",
					fh.Name, len(got), fh.UnpackedSize, err)
			}
			if int64(len(got)) >= fh.UnpackedSize {
				t.Fatalf("produced %d bytes against a declared size of %d, so nothing was actually truncated",
					len(got), fh.UnpackedSize)
			}
			// An error alone would not prove the caller is protected: io.Copy
			// converts io.EOF to nil, which is how this stayed invisible.
			if !errors.Is(err, ErrTruncatedFile) || errors.Is(err, io.EOF) {
				t.Fatalf("ErrTruncatedFile must not satisfy errors.Is(err, io.EOF): %v", err)
			}
		})
	}
}

// TestErrTruncatedFile_IsNotEOF pins the property the whole fix depends on.
// Callers loop until io.EOF, so a truncation error that satisfied errors.Is
// against io.EOF would be silently swallowed exactly as before.
func TestErrTruncatedFile_IsNotEOF(t *testing.T) {
	if errors.Is(ErrTruncatedFile, io.EOF) {
		t.Fatal("ErrTruncatedFile satisfies errors.Is(err, io.EOF), which reintroduces #21")
	}
}

// TestFileReader_ErrorIsSticky is the #23 reproduction. A second Read after a
// reported failure used to return a clean io.EOF, so any caller that kept
// reading had the verdict erased.
func TestFileReader_ErrorIsSticky(t *testing.T) {
	t.Run("crc mismatch", func(t *testing.T) {
		content := []byte("world")
		wrongCRC := crc32.ChecksumIEEE(content) ^ 0xFFFFFFFF
		sd := NewStreamDecompressor(newSingleVolumeChan(
			buildSingleFileRAR5Archive(t, "hello.txt", content, wrongCRC)))
		if _, err := sd.Next(); err != nil {
			t.Fatalf("Next() failed: %v", err)
		}
		assertSticky(t, sd, ErrCRCMismatch)
	})

	t.Run("truncation", func(t *testing.T) {
		full := fixtureBytes(t, "rar5_store.rar")
		sd := decompressorFor(full[:len(full)-10])
		if _, err := sd.Next(); err != nil {
			t.Fatalf("Next() failed: %v", err)
		}
		assertSticky(t, sd, ErrTruncatedFile)
	})
}

// assertSticky drains sd until it reports a failure, then confirms the next
// several reads report the same one rather than decaying to io.EOF.
func assertSticky(t *testing.T, sd *StreamDecompressor, want error) {
	t.Helper()

	buf := make([]byte, 4096)
	var first error
	for range 8 {
		_, err := sd.Read(buf)
		if err != nil {
			first = err
			break
		}
	}
	if !errors.Is(first, want) {
		t.Fatalf("expected %v from the reading loop, got %v", want, first)
	}

	for i := range 3 {
		n, err := sd.Read(buf)
		if !errors.Is(err, want) {
			t.Fatalf("read %d after the failure returned n=%d err=%v; want the original %v to persist",
				i, n, err, want)
		}
		if n != 0 {
			t.Fatalf("read %d after the failure produced %d bytes", i, n)
		}
	}
}

// resurrectingReader reports io.EOF once and then produces bytes again.
//
// It is a deliberate stand-in rather than a copy of any one decoder's
// behaviour: io.Reader permits this, and fileReader must hold regardless of
// which source it is wrapping. The decoders are not far from it -- rar3Decoder
// returns buffered window bytes while withholding a decode error -- but the
// guard under test is not conditional on that.
type resurrectingReader struct{ calls int }

func (r *resurrectingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'X'
	}
	return len(p), nil
}

// TestFileReader_TerminatedFileProducesNothingFurther pins the terminal-state
// guard in Read specifically.
//
// The stickiness of the *error* alone does not pin it: finish is idempotent,
// so the original error would be returned again regardless. What the guard
// adds is that no further bytes reach the caller once a file has failed --
// without it, a source that resumes yielding data after an error would have
// those bytes appended to a file already reported as truncated.
func TestFileReader_TerminatedFileProducesNothingFurther(t *testing.T) {
	var fr fileReader
	fr.begin(&FileHeader{Name: "resurrect.bin", UnpackedSize: 10}, &resurrectingReader{}, false)

	if n, err := fr.Read(make([]byte, 10)); n != 0 || !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("first read returned n=%d err=%v; want 0, ErrTruncatedFile", n, err)
	}

	buf := make([]byte, 10)
	n, err := fr.Read(buf)
	if n != 0 {
		t.Fatalf("a terminated file produced %d further bytes (%q); the source resumed "+
			"yielding data and the terminal guard did not stop it", n, buf[:n])
	}
	if !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("second read returned %v; want the original ErrTruncatedFile", err)
	}
}

// TestFileReader_SkipVerifies covers the drain path. Advancing past a file
// used to bypass the byte budget and the checksum entirely, so a corrupt file
// nobody read was never noticed.
func TestFileReader_SkipVerifies(t *testing.T) {
	content := []byte("world")

	t.Run("corrupt file skipped without reading fails Next", func(t *testing.T) {
		wrongCRC := crc32.ChecksumIEEE(content) ^ 0xFFFFFFFF
		sd := NewStreamDecompressor(newSingleVolumeChan(
			buildSingleFileRAR5Archive(t, "hello.txt", content, wrongCRC)))
		if _, err := sd.Next(); err != nil {
			t.Fatalf("first Next() failed: %v", err)
		}
		if _, err := sd.Next(); !errors.Is(err, ErrCRCMismatch) {
			t.Fatalf("skipping a corrupt file returned %v; want ErrCRCMismatch", err)
		}
	})

	t.Run("intact file skipped without reading does not fail Next", func(t *testing.T) {
		sd := NewStreamDecompressor(newSingleVolumeChan(
			buildSingleFileRAR5Archive(t, "hello.txt", content, crc32.ChecksumIEEE(content))))
		if _, err := sd.Next(); err != nil {
			t.Fatalf("first Next() failed: %v", err)
		}
		// End of archive, not a verification failure.
		if _, err := sd.Next(); !errors.Is(err, ErrNoNextVolume) {
			t.Fatalf("skipping an intact file returned %v; want ErrNoNextVolume", err)
		}
	})

	// Terminal is per file, not per archive: an error the caller already
	// received must not be raised again by the drain, or one corrupt file
	// would end the archive with no way past it.
	t.Run("failure already reported to the caller is not repeated", func(t *testing.T) {
		wrongCRC := crc32.ChecksumIEEE(content) ^ 0xFFFFFFFF
		sd := NewStreamDecompressor(newSingleVolumeChan(
			buildSingleFileRAR5Archive(t, "hello.txt", content, wrongCRC)))
		if _, err := sd.Next(); err != nil {
			t.Fatalf("first Next() failed: %v", err)
		}
		if _, err := io.ReadAll(sd); !errors.Is(err, ErrCRCMismatch) {
			t.Fatalf("reading the corrupt file returned %v; want ErrCRCMismatch", err)
		}
		if _, err := sd.Next(); errors.Is(err, ErrCRCMismatch) {
			t.Fatal("Next() repeated a failure the caller had already been given, " +
				"which would make one corrupt file end the archive")
		}
	})
}

// TestFileReader_MultiVolumeVerifiesAgainstLastHeader pins the reason the
// header is not captured when a file begins: for a multi-volume file the
// whole-file CRC32 is recorded in the LAST part's header. Pinning the first
// part's header would fail every multi-volume archive.
func TestFileReader_MultiVolumeVerifiesAgainstLastHeader(t *testing.T) {
	sd := NewStreamDecompressor(multiVolumeChan(t, -1))
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}
	firstCRC := fh.CRC32

	got, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("reading a multi-volume file failed: %v", err)
	}
	if int64(len(got)) != fh.UnpackedSize {
		t.Fatalf("read %d bytes, declared %d", len(got), fh.UnpackedSize)
	}

	// Without this the test could pass while still pinning the first header,
	// if both parts happened to record the same value.
	lastCRC := sd.file.header.CRC32
	if firstCRC == lastCRC {
		t.Fatalf("first and last part both record CRC %08x, so this fixture cannot "+
			"distinguish the two and the test proves nothing", firstCRC)
	}
	if crc32.ChecksumIEEE(got) != lastCRC {
		t.Fatalf("whole-file CRC %08x matches neither the last part's header %08x",
			crc32.ChecksumIEEE(got), lastCRC)
	}
}

// TestFileReader_MacChecksumIsRefusedNotMiscompared covers encrypted files
// whose header records a key-derived MAC rather than a CRC32 of the plaintext.
//
// Comparing the MAC as though it were a CRC32 fails on correctly decrypted
// content, which is what used to happen. Skipping the check instead would be
// worse: the flag that selects a MAC is attacker-supplied, so silently
// completing would let a crafted archive deliver arbitrary bytes reported as
// extracted successfully. Since this library cannot compute the MAC, it says
// so and fails.
//
// Verification is the caller's to disable, and doing so must still yield the
// content -- that is what SetVerifyCRC(false) is for.
func TestFileReader_MacChecksumIsRefusedNotMiscompared(t *testing.T) {
	// verify is applied before Next, because the decision is captured when a
	// file begins rather than re-read at completion.
	load := func(t *testing.T, verify bool) (*StreamDecompressor, *FileHeader) {
		t.Helper()
		sd := decompressorFor(fixtureBytes(t, "rar5_encrypted.rar"))
		sd.SetPassword("test")
		sd.SetVerifyCRC(verify)
		fh, err := sd.Next()
		if err != nil {
			t.Fatalf("Next() failed: %v", err)
		}
		if !fh.UseMac {
			t.Skip("fixture no longer uses a MAC checksum; this case tests nothing")
		}
		return sd, fh
	}

	t.Run("refused while verifying", func(t *testing.T) {
		sd, _ := load(t, true)
		_, err := io.ReadAll(sd)
		if !errors.Is(err, ErrChecksumUnsupported) {
			t.Fatalf("reading a MAC-checksummed file returned %v; want ErrChecksumUnsupported", err)
		}
		if errors.Is(err, ErrCRCMismatch) {
			t.Fatal("reported as a CRC mismatch, which misdescribes an unverifiable digest " +
				"as corrupt content")
		}
	})

	t.Run("delivered when verification is off", func(t *testing.T) {
		sd, fh := load(t, false)
		got, err := io.ReadAll(sd)
		if err != nil {
			t.Fatalf("reading with verification disabled failed: %v", err)
		}
		if int64(len(got)) != fh.UnpackedSize {
			t.Fatalf("read %d bytes, declared %d", len(got), fh.UnpackedSize)
		}
		if crc32.ChecksumIEEE(got) == fh.CRC32 {
			t.Fatal("the header checksum equals a plain CRC32 of the content, so this " +
				"fixture no longer demonstrates the MAC case")
		}
	})
}

// TestFileReader_AttackerFlagsCannotSkipVerification pins the two header bits
// that used to switch verification off.
//
// Both are attacker-supplied and neither is cross-checked against the entry
// actually carrying content, so gating on them let a crafted archive hand the
// caller arbitrary bytes with a clean io.EOF. IsDir is no longer consulted at
// all -- an entry that produced bytes is verified whatever it calls itself --
// and UseMac now refuses rather than skips.
func TestFileReader_AttackerFlagsCannotSkipVerification(t *testing.T) {
	content := []byte("attacker payload")
	const bogus = 0xDEADBEEF

	cases := []struct {
		name string
		fh   *FileHeader
		want error
	}{
		{
			name: "IsDir set on an entry carrying content",
			fh: &FileHeader{Name: "d", IsDir: true, HasCRC32: true, CRC32: bogus,
				UnpackedSize: int64(len(content))},
			want: ErrCRCMismatch,
		},
		{
			name: "UseMac set on an entry carrying content",
			fh: &FileHeader{Name: "e", UseMac: true, HasCRC32: true, CRC32: bogus,
				UnpackedSize: int64(len(content))},
			want: ErrChecksumUnsupported,
		},
		{
			name: "no flags, for comparison",
			fh: &FileHeader{Name: "c", HasCRC32: true, CRC32: bogus,
				UnpackedSize: int64(len(content))},
			want: ErrCRCMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fr fileReader
			fr.begin(tc.fh, bytes.NewReader(content), true)

			got, err := io.ReadAll(&fr)
			if !errors.Is(err, tc.want) {
				t.Fatalf("delivered %q with err=%v; want %v. A header flag must not be "+
					"able to turn verification off", got, err, tc.want)
			}
		})
	}
}

// TestParseFileHeader_RejectsNegativeSize covers a declared size with the sign
// bit set.
//
// The size vint carries more bits than an int64 sign-magnitude value, so a
// crafted header can make UnpackedSize negative. Downstream that value is
// compared against progress and used to clamp a slice, where it would panic
// and take the process down -- so it is rejected where it is decoded.
func TestParseFileHeader_RejectsNegativeSize(t *testing.T) {
	var payload bytes.Buffer
	payload.Write(EncodeVint(0))       // flags
	payload.Write(EncodeVint(1 << 63)) // unpacked size, sign bit set
	payload.Write(EncodeVint(0))       // attributes
	payload.Write(EncodeVint(0))       // compFlags
	payload.Write(EncodeVint(1))       // hostOS
	payload.Write(EncodeVint(4))       // name length
	payload.WriteString("evil")

	h := &BlockHeader{Type: HeaderTypeFile, Payload: payload.Bytes()}
	fh, err := ParseFileHeader(h)
	if err == nil {
		t.Fatalf("accepted a header declaring an unpacked size of %d", fh.UnpackedSize)
	}
	if !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("returned %v; want ErrCorruptFileHeader", err)
	}
}

// TestFileReader_NegativeRemainingDoesNotPanic is the backstop for the same
// hazard, in case a size ever reaches this type without passing a parser.
func TestFileReader_NegativeRemainingDoesNotPanic(t *testing.T) {
	var fr fileReader
	fr.begin(&FileHeader{Name: "evil", UnpackedSize: -1},
		bytes.NewReader(bytes.Repeat([]byte("A"), 64)), true)

	n, err := fr.Read(make([]byte, 16))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read returned n=%d err=%v; want 0, io.EOF", n, err)
	}
}

// TestFileReader_ChecksumSkippedWhenNotApplicable covers the cases where the
// running checksum means nothing, driving fileReader directly because no
// fixture combines them all.
func TestFileReader_ChecksumSkippedWhenNotApplicable(t *testing.T) {
	// A CRC32 that matches nothing, so any case that wrongly compares it fails.
	const bogus = 0xDEADBEEF

	cases := []struct {
		name    string
		header  *FileHeader
		content []byte
	}{
		{
			// Verified by producing nothing rather than by claiming to be a
			// directory: the flag is not consulted, the size is.
			name:    "entry with no content",
			header:  &FileHeader{Name: "dir", IsDir: true, HasCRC32: true, CRC32: bogus},
			content: nil,
		},
		{
			name:    "no checksum recorded",
			header:  &FileHeader{Name: "blake", HasCRC32: false, CRC32: bogus, UnpackedSize: 5},
			content: []byte("world"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fr fileReader
			fr.begin(tc.header, bytes.NewReader(tc.content), true)

			got, err := io.ReadAll(&fr)
			if err != nil {
				t.Fatalf("expected a clean completion, got %v", err)
			}
			if !bytes.Equal(got, tc.content) {
				t.Fatalf("read %q, want %q", got, tc.content)
			}
		})
	}
}

// TestFileReader_ZeroLengthFileCompletes checks the file that never enters the
// read path at all: with nothing owed, termination has to be decided up front
// or it is never decided.
func TestFileReader_ZeroLengthFileCompletes(t *testing.T) {
	var fr fileReader
	fr.begin(&FileHeader{Name: "empty", HasCRC32: true, CRC32: crc32.ChecksumIEEE(nil)},
		bytes.NewReader(nil), true)

	n, err := fr.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("zero-length file returned n=%d err=%v; want 0, io.EOF", n, err)
	}
}

// TestFileReader_ReadBeforeNextReportsNoActiveFile keeps "nothing started"
// distinguishable from "finished", which collapsing them into io.EOF would
// lose.
func TestFileReader_ReadBeforeNextReportsNoActiveFile(t *testing.T) {
	sd := NewStreamDecompressor(nil)
	if _, err := sd.Read(make([]byte, 8)); !errors.Is(err, ErrNoActiveFile) {
		t.Fatalf("Read before Next returned %v; want ErrNoActiveFile", err)
	}
}

// TestFileReader_ResetClearsTerminalState guards the reuse path: the window and
// decompressor are deliberately reused, so a terminal error left behind would
// make the next stream fail before it started.
func TestFileReader_ResetClearsTerminalState(t *testing.T) {
	content := []byte("world")
	wrongCRC := crc32.ChecksumIEEE(content) ^ 0xFFFFFFFF
	sd := NewStreamDecompressor(newSingleVolumeChan(
		buildSingleFileRAR5Archive(t, "hello.txt", content, wrongCRC)))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next() failed: %v", err)
	}
	if _, err := io.ReadAll(sd); !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("expected ErrCRCMismatch, got %v", err)
	}

	sd.Reset(newSingleVolumeChan(
		buildSingleFileRAR5Archive(t, "second.txt", content, crc32.ChecksumIEEE(content))))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next() after Reset failed: %v", err)
	}
	got, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("reading after Reset failed, so the previous stream's terminal state survived: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("read %q after Reset, want %q", got, content)
	}
}

// TestFileReader_ResetMidFileDropsTheOldFile covers resetting away from a file
// that is still partly unread, which is the case that needs the active file
// dropped rather than drained.
//
// The abandoned file is one that would fail verification. If it survived
// Reset, the endFile beginning the next Next() would drain it, discover the
// failure, and report the previous archive's error against the new stream --
// before the new stream had produced anything at all.
func TestFileReader_ResetMidFileDropsTheOldFile(t *testing.T) {
	first := []byte("the first stream's content")
	sd := NewStreamDecompressor(newSingleVolumeChan(
		buildSingleFileRAR5Archive(t, "first.txt", first, crc32.ChecksumIEEE(first)^0xFFFFFFFF)))
	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next() failed: %v", err)
	}
	// Deliberately partial: bytes are still owed when Reset lands.
	if _, err := sd.Read(make([]byte, 4)); err != nil {
		t.Fatalf("partial read failed: %v", err)
	}

	second := []byte("the second stream's content")
	sd.Reset(newSingleVolumeChan(
		buildSingleFileRAR5Archive(t, "second.txt", second, crc32.ChecksumIEEE(second))))

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() after a mid-file Reset failed, so the abandoned file was still "+
			"installed and the new stream inherited its verdict: %v", err)
	}
	if fh.Name != "second.txt" {
		t.Fatalf("Next() returned %q, want second.txt", fh.Name)
	}
	got, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("reading the new stream failed: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("read %q, want %q", got, second)
	}
}

// TestFileReader_DrainLeavesStreamPositioned checks that consuming a file
// through the owner, which stops at the declared size, leaves the packed
// stream where the next header begins. The previous drain read to the
// underlying EOF instead, so this could have been load-bearing.
func TestFileReader_DrainLeavesStreamPositioned(t *testing.T) {
	sd := decompressorFor(fixtureBytes(t, "rar5_compress.rar"))

	first, err := sd.Next()
	if err != nil {
		t.Fatalf("first Next() failed: %v", err)
	}
	if _, err := io.ReadAll(sd); err != nil {
		t.Fatalf("reading %q failed: %v", first.Name, err)
	}

	second, err := sd.Next()
	if err != nil {
		t.Fatalf("second Next() failed, so the drain left the stream mispositioned: %v", err)
	}
	if second.Name == first.Name {
		t.Fatalf("second Next() returned the same file %q", second.Name)
	}
	if _, err := io.ReadAll(sd); err != nil {
		t.Fatalf("reading %q failed: %v", second.Name, err)
	}
}

// TestFileReader_ShortFileStopsTraversal pins the boundary of the skip
// contract.
//
// A file that failed but still delivered its declared size has had its packed
// payload consumed, so the caller can move past it -- that is the CRC-mismatch
// case, and TestFileReader_SkipVerifies covers it. A file that stopped short
// has not: an unknown number of its packed bytes remain, and this type only
// sees the decompressed side. Continuing there would leave the next block
// header to be parsed out of that payload, so Next must report the failure
// rather than resynchronise onto it.
//
// Draining the packed remainder to make this case skippable too is follow-up
// work; until then the archive ending here is the safe answer, and is what
// the previous drain-to-EOF did as well.
func TestFileReader_ShortFileStopsTraversal(t *testing.T) {
	full := fixtureBytes(t, "rar5_store.rar")
	sd := decompressorFor(full[:len(full)-10])

	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next() failed: %v", err)
	}
	if _, err := io.ReadAll(sd); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the truncated file returned %v; want ErrTruncatedFile", err)
	}

	// Already reported to the caller, but the packed side is still unread, so
	// this must not be treated as a file that can be stepped over.
	if _, err := sd.Next(); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("Next() after a short file returned %v; want ErrTruncatedFile. "+
			"Continuing would parse the next header out of the unread payload", err)
	}
}

// TestUnknownUnpackedSizeIsSkippable checks that refusing a file does not
// leave its payload in the stream for the next header read to land in.
func TestUnknownUnpackedSizeIsSkippable(t *testing.T) {
	// Distinctive so its presence in the unread remainder is unambiguous.
	content := []byte("PAYLOAD-MUST-BE-DISCARDED")
	buf := buildSingleFileRAR5ArchiveFlags(t, "streamed.txt", content,
		crc32.ChecksumIEEE(content), FileFlagUnpSizeUnknown)

	sd := NewStreamDecompressor(newSingleVolumeChan(buf))

	if _, err := sd.Next(); !errors.Is(err, ErrUnpSizeUnknown) {
		t.Fatalf("Next() returned %v; want ErrUnpSizeUnknown", err)
	}

	// Assert on what is left in the stream rather than on the next Next()'s
	// error. A leftover payload usually makes the following header read fail
	// with something that happens to end in ErrNoNextVolume anyway, so an
	// error-only assertion passes whether or not the payload was dropped.
	if bytes.Contains(buf.Bytes(), content) {
		t.Fatalf("the refused file's payload is still unread in the stream; the next "+
			"header would be parsed out of it. Remaining: %q", buf.Bytes())
	}
}

func TestRAR3_RealArchive_Header(t *testing.T) {
	sd := decompressorFor(fixtureBytes(t, "rar3_testfile.rar"))

	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() on a real RAR3 archive failed: %v", err)
	}
	if fh.Name != "testfile.txt" {
		t.Errorf("parsed name %q, want testfile.txt", fh.Name)
	}
	if fh.UnpackedSize != 12 {
		t.Errorf("parsed unpacked size %d, want 12", fh.UnpackedSize)
	}
	if sd.Version() != VersionRAR3 {
		t.Errorf("detected version %v, want RAR3", sd.Version())
	}

	_, err = io.ReadAll(sd)
	if !errors.Is(err, ErrPPMUnsupported) {
		t.Fatalf("reading a PPMd file returned %v; want ErrPPMUnsupported, "+
			"not a truncation or checksum verdict", err)
	}
	// The decode error must not decay on a further read.
	if _, err := sd.Read(make([]byte, 8)); !errors.Is(err, ErrPPMUnsupported) {
		t.Fatalf("reading again returned %v; want the decode error to persist", err)
	}
}

// TestParseFileHeader_RejectsUnknownUnpackedSize covers the flag that makes
// the declared size meaningless. Detecting truncation depends on that size, so
// a header declining to state it is refused rather than decoded against a
// value that means nothing.
func TestParseFileHeader_RejectsUnknownUnpackedSize(t *testing.T) {
	h := &BlockHeader{
		Type:    HeaderTypeFile,
		Payload: EncodeVint(FileFlagUnpSizeUnknown),
	}
	if _, err := ParseFileHeader(h); !errors.Is(err, ErrUnpSizeUnknown) {
		t.Fatalf("ParseFileHeader returned %v; want ErrUnpSizeUnknown", err)
	}
}
