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
	// (FileFlagHasCRC32); verification is unconditional -- there is no
	// method to disable it.
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
	// A RAR3 signature reaches this: it is recognised so it can be refused
	// by name, and nothing beyond the signature is parsed.
	ErrUnsupportedFormat = errors.New("rarengine: unsupported archive format")

	// ErrTruncatedFile is returned when the archive stream ends before a file's
	// declared UnpackedSize has been produced. It deliberately does not satisfy
	// errors.Is(err, io.EOF): reporting truncation as a clean end of stream is
	// exactly the defect it exists to prevent, and callers loop until io.EOF.
	ErrTruncatedFile = errors.New("rarengine: archive ended before the file's declared size was produced")

	// ErrChecksumUnsupported is returned once a file has produced bytes that
	// this library could not compare against any digest. Three archive classes
	// reach it, and they are one verdict because a caller can do only one thing
	// about them:
	//
	//   - UseMac: the header's digest field holds a key-derived MAC rather than
	//     a CRC32 of the plaintext. RAR sets that flag on the header carrying
	//     the digest, which for a multi-volume file is the last part's.
	//   - BLAKE2sp only: written by rar -htb, which records a BLAKE2sp hash and
	//     no CRC32 at all. This library does not compute BLAKE2sp.
	//   - No digest recorded at all.
	//
	// Completing such a file without an error would report unverified content as
	// extracted successfully, and a RAR archive's per-file digest is the only
	// signal that the decoded bytes are the intended ones. There is no method
	// to disable verification and get the content regardless.
	//
	// The bytes are still delivered: this reports that a check could not be
	// made, not that the content is bad. A caller whose policy accepts
	// unverifiable content treats it as success; one that does not, does not.
	// A member that produced no bytes -- a directory, an empty file -- never
	// reaches this, because it has nothing to verify.
	ErrChecksumUnsupported = errors.New("rarengine: file records a checksum this library cannot verify")

	// ErrCorruptArchiveHeader reports that the archive-level header (the
	// block that declares archive-wide semantics, including whether the
	// archive is solid) failed to parse. Traversal has ended: Reader latches
	// this error and every subsequent NextEntry call returns it again
	// without reading further, because the stream is left positioned past a
	// block whose bytes could not be trusted, and continuing risks handing
	// back a member fabricated from attacker-chosen content. Reset clears
	// the latch. The underlying parse failure -- typically ErrTruncatedVint
	// -- is still reachable through errors.Is via the wrap.
	ErrCorruptArchiveHeader = errors.New("rarengine: archive header is corrupt, traversal ended")

	// ErrUnsupportedEncryptionVersion is returned when the archive's
	// encryption header (HEAD_CRYPT) declares an encryption version this
	// library does not implement -- the RAR 5.0 spec fixes the version vint
	// at 0 (AES-256); any other value names a scheme introduced by a newer
	// RAR version.
	//
	// The archive is not necessarily damaged: a future RAR wrote a header
	// this library is simply too old to read. That is a different condition
	// from corruption, and callers that want to tell an operator "upgrade
	// this tool" apart from "the download is bad, re-fetch or repair" need
	// to be able to distinguish the two -- see ErrCorruptArchiveHeader for
	// the corruption case. errors.Is(err, ErrUnknownEncryptMethod) still
	// reaches the underlying detail through the wrap.
	//
	// Traversal has ended regardless of which condition applies: once a
	// HEAD_CRYPT block is present, every header after it is ciphertext this
	// library cannot decrypt, so there is no degraded-but-useful mode to
	// fall back to. Reader latches this error and every subsequent
	// NextEntry call returns it again without reading further.
	ErrUnsupportedEncryptionVersion = errors.New("rarengine: archive declares an unsupported encryption version")

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
	// a digest it cannot check -- is not covered, because nothing observed the
	// damage.
	ErrSolidStreamBroken = errors.New("rarengine: solid file depends on history a damaged file did not write")
)
