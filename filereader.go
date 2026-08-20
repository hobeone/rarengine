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
// its header records a digest this library cannot check -- the key-derived
// MAC selected by UseMac, rather than a CRC32 of the plaintext. RAR sets that
// flag on the header carrying the digest, which for a multi-volume file is
// the last part's.
//
// Completing such a file without an error would report unverified content as
// extracted successfully, and a RAR archive's per-file digest is the only
// signal that the decoded bytes are the intended ones. Callers that want the
// content regardless can disable verification; see SetVerifyCRC.
var ErrChecksumUnsupported = errors.New("rarengine: file records a checksum this library cannot verify")

// ErrSolidStreamBroken is returned when a solid file cannot be decoded
// because an earlier file in the same solid run was damaged.
//
// Solid files share one LZ77 history: a file's back-references reach into the
// bytes its predecessors wrote. A predecessor that ended short never wrote
// some of them; one that failed its CRC32 wrote the wrong ones. Either way the
// successor decodes against history the archive did not assume, producing
// plausible-looking output with nothing in the format to mark it -- so both
// count as damage. Refusing is the only answer that cannot silently hand over
// fabricated content. A non-solid file resets the window and clears the
// condition, so a solid run beginning after the damage is unaffected.
//
// A predecessor whose content was wrong in a way this library cannot detect --
// verification disabled via SetVerifyCRC, or a digest it cannot check -- is not
// covered, because nothing observed the damage.
var ErrSolidStreamBroken = errors.New("rarengine: solid file depends on history a damaged file did not write")

// FileError reports that one file could not be delivered while the archive
// itself is still readable, and is what makes skipping a damaged file
// possible without guessing.
//
// Next returns it in place of the next header. The stream is already
// positioned at the following block when it is returned -- the failed file's
// packed remainder has been drained -- so calling Next again continues the
// traversal. Any other error means traversal has stopped.
//
// That distinction is the whole point of the type. Both outcomes previously
// arrived as the same bare error, so a caller had no way to tell "this file
// is unreadable, the rest are fine" from "the archive is over", and the only
// safe reading was to stop and lose every later file.
//
// Header identifies the file that failed. It is the part header in force when
// the failure was decided, which for a file spanning volumes is the LAST
// part's, not the one Next originally returned: Name matches, but FirstBlock
// is false and PackedSize describes only that part. Use it to name the file,
// not to describe the whole entry.
//
// Unwrap exposes the underlying cause, so errors.Is(err, ErrTruncatedFile)
// and the other sentinels keep working.
type FileError struct {
	Header *FileHeader
	Err    error
}

func (e *FileError) Error() string { return e.Err.Error() }

// Unwrap keeps errors.Is/As working through the wrapper, so a caller that
// does not care about the distinction behaves exactly as before.
func (e *FileError) Unwrap() error { return e.Err }

// markContinuable is the ONLY place a FileError is constructed.
//
// The type's promise -- that the traversal may resume -- is worth exactly what
// the check behind it is worth, so that check lives in one named function
// whose signature demands the proof. A second construction site that forgot to
// establish canContinue would hand callers a licence to read on from an
// offset nothing has verified, which is how a block header gets parsed out of
// a previous file's payload.
func markContinuable(fh *FileHeader, cause error, canContinue bool) error {
	if cause == nil || !canContinue {
		return cause
	}
	return &FileError{Header: fh, Err: cause}
}

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

	// accumulate reports whether verification is on for this file, and so
	// whether a running CRC32 is worth computing.
	//
	// It is fixed when the file begins and depends on nothing but the
	// caller's SetVerifyCRC choice. In particular it must not depend on the
	// part header in force -- comparison happens against the LAST header, so
	// gating accumulation on a per-part value could compare a checksum
	// covering only some of the file's bytes. Accumulation is therefore a
	// strict superset of comparison, and whether the recorded digest is one
	// this library can check is decided at completion, by verifyChecksum,
	// against the header that actually records it.
	//
	// It deliberately does NOT consult IsDir. That flag is attacker-supplied
	// and is not cross-checked against the entry carrying content, so
	// skipping verification on it let a crafted archive deliver arbitrary
	// bytes under a header claiming to be a directory. verifyChecksum skips
	// on the produced size instead, which is a value this type enforces.
	accumulate bool

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
	fr.accumulate = verifyCRC
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
	// UseMac is read here rather than at begin because it belongs to the
	// header that records the digest, which for a multi-volume file is the
	// LAST part's -- and RAR sets it only there. Reading it at begin saw the
	// first part's cleared copy and then compared a plaintext CRC32 against a
	// key-derived MAC, a guaranteed false ErrCRCMismatch on every encrypted
	// multi-volume file. Part 11 is the only part of either encrypted
	// multi-volume fixture with UseMac set.
	//
	// Parts 1 to 10 do carry a CRC32 field, so HasCRC32 below is NOT a
	// backstop against completing on a non-final header: that field covers
	// the part's own packed bytes rather than the file's plaintext, and this
	// parser cannot tell the two apart -- header.go sets HasCRC32 from the
	// same flag on every part. Completing while an intermediate header is in
	// force would miscompare against it, which is a separate problem from the
	// one this gate solves.
	//
	// The gate is UseMac and not Encrypted: encryption alone does not make a
	// digest uncheckable, RAR says so by setting this flag. Gating on
	// Encrypted would also hand RAR3 -- which never sets UseMac and never
	// decrypts -- a header bit that switches CRC verification off.
	if fr.accumulate && fr.header.UseMac {
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
func (fr *fileReader) endFile(packed *packedCursor) (damaged bool, err error) {
	if fr.src == nil {
		return false, nil
	}
	reported := fr.done
	_, contentErr := io.Copy(io.Discard, fr)
	// Captured before clear: whether the file delivered everything it
	// promised decides whether traversal can continue, and which file to name
	// when reporting that it did not.
	short := fr.remaining > 0
	failed := fr.header
	// Drained on every terminal path, not only the failing ones. A file that
	// completed perfectly can still leave packed bytes behind, and that is
	// exactly the case an archive uses to fabricate the next entry.
	packedErr := packed.drain()
	// Read before invalidate, which sets abandoned: afterwards every cursor
	// reports unsettled, and no file could be offered as continuable at all.
	settled := packed.settled()
	// The cursor described this file. Dropping the count here keeps a short
	// drain -- a truncated volume, where the promised bytes were never on the
	// media -- from leaving a stale count for whatever runs next.
	packed.invalidate()
	fr.clear()

	// outcome is what actually happened to this file's content, whether or not
	// the caller has already been told about it. The verdict below answers a
	// different question -- what to return now -- and deliberately reports
	// nothing for a failure already delivered.
	outcome := reported
	if outcome == nil {
		outcome = contentErr
	}
	// damaged asks about the window, not about the caller. A file that ended
	// short left bytes unwritten; one that failed its CRC32 wrote the wrong
	// ones. Either way a solid successor back-references history that is not
	// what the archive assumed, so both have to count -- keying this on short
	// alone let a CRC-mismatched predecessor admit a solid file that then
	// decoded against known-bad bytes.
	damaged = short || errors.Is(outcome, ErrCRCMismatch)

	var verdict error
	switch {
	case short:
		// The file stopped before its declared size. Its packed remainder has
		// been drained by now, so the stream sits at a real block boundary and
		// traversal can continue -- but only a caller that can tell this
		// failure apart from "the archive is over" may act on that, or the
		// permissive reading silently truncates whatever it is assembling.
		// FileError is what carries the difference; it is applied below, once
		// the drain is known to have succeeded.
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

	switch {
	case packedErr == nil:
		// settled alone, not short && settled. A file that reached its
		// declared size and then failed its checksum is just as continuable --
		// the cursor is drained and the stream is on the next header -- and
		// requiring short left the commonest damage signal in a Usenet
		// download reported as an error indistinguishable from end-of-archive.
		return damaged, markContinuable(failed, verdict, settled)
	case verdict == nil:
		// Returned unwrapped. errors.Join builds a wrapper even around a
		// single error, which costs an allocation and defeats the identity
		// comparisons callers use to recognise a sentinel.
		return damaged, packedErr
	default:
		// Both are meaningful and neither subsumes the other: the verdict says
		// what happened to the file, the drain error says the stream is no
		// longer positioned at a block boundary. Returning either alone loses
		// something the caller needs.
		return damaged, errors.Join(verdict, packedErr)
	}
}

// clear drops the active file. The zero value reports ErrNoActiveFile from
// Read rather than io.EOF, so reading before the first Next() stays
// distinguishable from reading past the end of one.
func (fr *fileReader) clear() {
	*fr = fileReader{}
}
