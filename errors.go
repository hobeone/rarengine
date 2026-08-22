package rarengine

import "errors"

var (
	// ErrNoNextVolume is returned when the archive stream ends before a
	// declared continuation is satisfied: the volumes channel closed while a
	// next volume was still expected.
	ErrNoNextVolume = errors.New("rarengine: expected next volume stream from channel, but channel was closed")

	// ErrNoActiveFile is returned when there is no active file stream to
	// read from.
	ErrNoActiveFile = errors.New("rarengine: no active file stream to read from")

	// ErrRarBombDetected is returned when a file's declared UnpackedSize is
	// disproportionate to its PackedSize, guarding against decompression
	// bombs.
	ErrRarBombDetected = errors.New("rarengine: possible RAR-bomb detected")

	// ErrCRCMismatch is returned by Read once a file's fully decompressed
	// content has been read, if its CRC32 doesn't match the value recorded
	// in the RAR file header. Only checked when the header carries a CRC32
	// (FileFlagHasCRC32) and VerifyCRC is enabled (the default). See
	// SetVerifyCRC.
	ErrCRCMismatch = errors.New("rarengine: decompressed content CRC32 does not match file header")

	// ErrWrongPassword is returned when an encrypted file's password check
	// value (PSWCHECK) doesn't match the supplied password. Wrap-checked
	// via errors.Is so callers can distinguish a bad password from other
	// decompression failures without parsing error text.
	ErrWrongPassword = errors.New("rarengine: wrong password or corrupt encryption data")

	// ErrPasswordRequired is returned when a file's header is encrypted but
	// no password was supplied. Callers that want to treat "no password
	// given" the same as "wrong password" (e.g. to prompt for one) can
	// check for either with errors.Is.
	ErrPasswordRequired = errors.New("rarengine: password required for encrypted file")

	// ErrUnsupportedFormat reports an archive this library cannot decode.
	// RAR3 archives reach this: their headers remain parseable through
	// ReadRAR3BlockHeader and ParseRAR3FileHeader for callers that inspect
	// archives, but no RAR3 decoder is provided.
	ErrUnsupportedFormat = errors.New("rarengine: unsupported archive format")

	// ErrTruncatedFile is returned when the archive stream ends before a file's
	// declared UnpackedSize has been produced. It deliberately does not satisfy
	// errors.Is(err, io.EOF): reporting truncation as a clean end of stream is
	// exactly the defect it exists to prevent, and callers loop until io.EOF.
	ErrTruncatedFile = errors.New("rarengine: archive ended before the file's declared size was produced")

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
	ErrChecksumUnsupported = errors.New("rarengine: file records a checksum this library cannot verify")

	// ErrSolidStreamBroken is returned when a solid file cannot be decoded
	// because an earlier file in the same solid run was damaged.
	//
	// Solid files share one LZ77 history: a file's back-references reach into the
	// bytes its predecessors wrote. A predecessor that ended short never wrote
	// some of them; one that failed its CRC32 wrote the wrong ones; one that was
	// refused before it decoded -- a rar bomb, an unparsable header -- wrote none
	// at all. In every case the successor decodes against history the archive did
	// not assume, producing plausible-looking output with nothing in the format to
	// mark it, so all three count as damage. Refusing is the only answer that cannot silently hand over
	// fabricated content. A non-solid file resets the window and clears the
	// condition, so a solid run beginning after the damage is unaffected.
	//
	// A predecessor whose content was wrong in a way this library cannot detect --
	// verification disabled via SetVerifyCRC, or a digest it cannot check -- is not
	// covered, because nothing observed the damage.
	ErrSolidStreamBroken = errors.New("rarengine: solid file depends on history a damaged file did not write")
)
