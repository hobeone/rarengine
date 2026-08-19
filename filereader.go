package rarengine

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// ErrTruncatedFile is returned when the archive stream ends before a file's
// declared UnpackedSize has been produced. It deliberately does not satisfy
// errors.Is(err, io.EOF): reporting truncation as a clean end of stream is
// exactly the defect it exists to prevent, and callers loop until io.EOF.
var ErrTruncatedFile = errors.New("rarengine: archive ended before the file's declared size was produced")

// ErrChecksumUnsupported is returned once a file has been fully decoded when
// its header records a digest this library cannot check -- currently the
// key-derived MAC that encrypted files use in place of a CRC32.
//
// Completing such a file without an error would report unverified content as
// extracted successfully, and a RAR archive's per-file digest is the only
// signal that the decoded bytes are the intended ones. Callers that want the
// content regardless can disable verification; see SetVerifyCRC.
var ErrChecksumUnsupported = errors.New("rarengine: file records a checksum this library cannot verify")

// fileReader owns every piece of state that belongs to one file being
// decoded: the reader chain it comes from, the header in force, how many
// bytes are still owed, the running checksum, and whether the file has
// terminated.
//
// It exists because that state used to be spread across three types and
// mutated from five places, which is what let a file end without anyone
// deciding whether it had ended successfully. Both #21 (a truncated file
// reported as a clean io.EOF) and #23 (a decoder that kept serving after an
// error) were instances of the same gap: nothing owned the notion of a file
// being finished.
//
// Mutation happens only through begin, advanceVolume, Read, finish and
// endFile. Anything else touching these fields reopens that gap.
type fileReader struct {
	// src is the decompression reader chain for the current file.
	// nil means no file is active.
	src io.Reader

	// header is the file header currently in force, which is NOT constant
	// across a file: see advanceVolume.
	//
	// It is non-nil exactly while src is, because begin sets both and clear
	// drops both. Every method below that reads it is reachable only while a
	// file is active, so none of them guards against nil.
	header *FileHeader

	// size is the declared size captured when the file began, kept separately
	// from header.UnpackedSize so that a truncation report stays accurate
	// even though header is replaced mid-file.
	size int64

	// remaining counts bytes still owed to the caller. Reaching zero is what
	// makes a file complete; ending the stream before it does is truncation.
	remaining int64

	crc uint32

	// accumulate reports whether a running CRC32 is worth computing for this
	// file: verification is on, and the recorded digest is one this library
	// can actually check.
	//
	// It is fixed when the file begins because it must not depend on the part
	// header in force -- comparison happens against the LAST header, so
	// gating accumulation on a per-part value could compare a checksum
	// covering only some of the file's bytes. Accumulation is therefore a
	// strict superset of comparison.
	//
	// It deliberately does NOT consult IsDir. That flag is attacker-supplied
	// and is not cross-checked against the entry carrying content, so
	// skipping verification on it let a crafted archive deliver arbitrary
	// bytes under a header claiming to be a directory. verifyChecksum skips
	// on the produced size instead, which is a value this type enforces.
	accumulate bool

	// unverifiable records that the file's digest is a key-derived MAC
	// rather than a CRC32 of the plaintext, so the recorded value cannot be
	// checked here. Completing such a file silently would report unverified
	// attacker-chosen content as extracted successfully, so finish turns it
	// into an error instead -- unless the caller has opted out of
	// verification, which is what SetVerifyCRC(false) means.
	unverifiable bool

	// done is the terminal state. Once set, every Read returns it and the
	// file produces nothing further. It is what makes an error durable
	// rather than something the next Read can erase.
	done error
}

// begin installs a file as the active one. src must already be fully
// constructed: the multi-volume readers consult the header through this type
// while reading, so both must be in place before the first Read.
func (fr *fileReader) begin(fh *FileHeader, src io.Reader, verifyCRC bool) {
	fr.src = src
	fr.header = fh
	fr.size = fh.UnpackedSize
	fr.remaining = fh.UnpackedSize
	fr.crc = 0
	fr.accumulate = verifyCRC && !fh.UseMac
	fr.unverifiable = verifyCRC && fh.UseMac
	fr.done = nil
}

// advanceVolume replaces the header in force when a file's payload continues
// into the next volume.
//
// This is a real mid-file mutation, not bookkeeping: for a multi-volume file
// the whole-file CRC32 is recorded in the LAST part's header, not the first,
// so verification at completion must read the header as it stands then. The
// multi-volume readers also consult LastBlock through lastBlock() to decide
// whether an inner io.EOF ends the file or means "fetch the next volume".
//
// It is a named transition rather than a bare field write so that the one
// place allowed to swap the header mid-file stays visible.
func (fr *fileReader) advanceVolume(fh *FileHeader) {
	fr.header = fh
}

// lastBlock reports whether the header in force marks the final block of the
// file, which is how the multi-volume readers tell a real end of file from a
// volume boundary.
func (fr *fileReader) lastBlock() bool {
	return fr.header.LastBlock
}

// Read produces the file's decompressed bytes, and is the only path that
// advances the byte budget or the running checksum.
func (fr *fileReader) Read(p []byte) (int, error) {
	// Behavioural rule: a terminated file yields no further bytes. This is
	// not the same check as the one in finish, which protects the recorded
	// verdict; this one protects the caller. Both are needed.
	//
	// It holds whatever the source does afterwards. io.Reader does not forbid
	// a reader from producing data once it has reported a failure, and the
	// decoders below are stateful enough that arguing case by case is not
	// worth depending on -- rar3Decoder, for one, already returns buffered
	// window bytes while withholding a decode error. Without this guard those
	// bytes would be appended to a file the caller was already told had
	// failed.
	if fr.done != nil {
		return 0, fr.done
	}
	if fr.src == nil {
		return 0, ErrNoActiveFile
	}
	// A zero-length file never enters the read path below, so completing it
	// here is what gives it a terminal state (and a checksum check) at all.
	//
	// Tested with <= rather than ==: the parsers reject a negative declared
	// size, and this is the backstop for that. Reaching the clamp below with
	// a negative remaining would panic on the slice bound, turning a crafted
	// header into a process kill.
	if fr.remaining <= 0 {
		return 0, fr.finish(nil)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > fr.remaining {
		p = p[:fr.remaining]
	}

	n, err := fr.src.Read(p)
	if n > 0 && fr.accumulate {
		fr.crc = crc32.Update(fr.crc, crc32.IEEETable, p[:n])
	}
	fr.remaining -= int64(n)

	switch {
	case err == nil && fr.remaining == 0:
		return n, fr.finish(nil)
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF) && fr.remaining > 0:
		// The stream ended with bytes still owed. This is the case that used
		// to be passed through as a clean io.EOF and read as success.
		return n, fr.finish(fr.truncated())
	case errors.Is(err, io.EOF):
		return n, fr.finish(nil)
	default:
		return n, fr.finish(err)
	}
}

// finish records the file's terminal state, once, and returns it. A nil err
// means the byte budget was met, which is when the checksum is judged.
// Success is recorded as io.EOF so that every terminal state is an error
// value and Read has exactly one thing to return.
func (fr *fileReader) finish(err error) error {
	// State rule: the first verdict wins and is never overwritten. Read's
	// guard means this is currently unreachable, but the two protect
	// different things -- that one stops bytes escaping, this one stops a
	// second call downgrading a recorded ErrCRCMismatch to io.EOF. Keep it
	// here, with the mutation it guards.
	if fr.done != nil {
		return fr.done
	}
	if err == nil {
		err = fr.verifyChecksum()
	}
	if err == nil {
		err = io.EOF
	}
	fr.done = err
	return fr.done
}

// verifyChecksum compares the running CRC32 against the header in force at
// completion. For a multi-volume file that is the LAST part's header, which
// is where the whole-file CRC32 is recorded.
//
// A file can complete without being verified: a BLAKE2sp-only archive
// records no CRC32 at all, and this library does not check BLAKE2sp. So
// "terminated cleanly" does not imply "content was verified".
func (fr *fileReader) verifyChecksum() error {
	if fr.unverifiable {
		return fmt.Errorf("%w: file %q", ErrChecksumUnsupported, fr.header.Name)
	}
	// Nothing was delivered, so there is nothing to verify. This is what
	// covers directory entries, without trusting the IsDir flag to tell the
	// truth: an entry that produced bytes is checked whatever it calls
	// itself, and one that produced none has nothing to check.
	if fr.size == 0 || !fr.accumulate || !fr.header.HasCRC32 {
		return nil
	}
	if fr.crc != fr.header.CRC32 {
		return fmt.Errorf("%w: file %q: computed=%08x header=%08x",
			ErrCRCMismatch, fr.header.Name, fr.crc, fr.header.CRC32)
	}
	return nil
}

func (fr *fileReader) truncated() error {
	return fmt.Errorf("%w: file %q: got %d of %d bytes",
		ErrTruncatedFile, fr.header.Name, fr.size-fr.remaining, fr.size)
}

// endFile consumes whatever the caller left unread and clears the active
// file. It is how advancing past a file verifies it on the same terms as
// reading it.
//
// A failure the caller already received from Read is not raised again --
// reporting it once is enough, and repeating it would make one corrupt file
// end the archive with no way past it, which is the workflow
// SetVerifyCRC(false) exists to support. That only applies when the file
// actually produced its declared size, though: see below.
// packed is the engine's cursor over the bytes the current file's block still
// owes the stream. It is passed in rather than held as a field because the
// engine repoints it on every volume advance: read at the point of use it is
// current by construction, where a copy kept here would describe whichever
// volume the file started on.
func (fr *fileReader) endFile(packed *packedCursor) error {
	if fr.src == nil {
		return nil
	}
	reported := fr.done
	_, contentErr := io.Copy(io.Discard, fr)
	// Captured before clear: whether the file delivered everything it
	// promised decides whether traversal can continue.
	short := fr.remaining > 0
	// Drained on every terminal path, not only the failing ones. A file that
	// completed perfectly can still leave packed bytes behind, and that is
	// exactly the case an archive uses to fabricate the next entry.
	packedErr := packed.drain()
	fr.clear()

	var verdict error
	switch {
	case short:
		// The file stopped before its declared size. Its packed remainder is
		// drained by now, so the stream sits at a real block boundary and
		// traversal *could* continue -- but a caller cannot tell this failure
		// apart from "the archive is over", and the permissive guess silently
		// truncates whatever it is assembling. Reporting is the reading that
		// cannot lose data, until the error contract can carry the difference.
		verdict = reported
		if verdict == nil {
			verdict = contentErr
		}
	case reported != nil:
		// Already delivered to the caller once; saying it again would make one
		// corrupt file an archive nobody can read past.
		verdict = nil
	default:
		verdict = contentErr
	}

	if packedErr == nil {
		return verdict
	}
	// Both are meaningful and neither subsumes the other: the verdict says what
	// happened to the file, the drain error says the stream is no longer
	// positioned at a block boundary. Returning either alone loses something
	// the caller needs.
	return errors.Join(verdict, packedErr)
}

// clear drops the active file. The zero value reports ErrNoActiveFile from
// Read rather than io.EOF, so reading before the first Next() stays
// distinguishable from reading past the end of one.
func (fr *fileReader) clear() {
	*fr = fileReader{}
}
