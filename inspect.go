package rarengine

import (
	"errors"
	"fmt"
	"io"
)

// Inspection entry points: read-only questions about an archive that
// traversal cannot answer.
//
// Both take a reader positioned at the START of the archive and consume the
// signature themselves. Neither decompresses anything, neither decrypts
// anything, and neither reads a block's payload except to skip past it.
//
// These exist because the header parsers they replace used to be exported and
// were the only way to ask either question. Those parsers are now unexported
// -- a caller holding a blockHeader could drive the decoders past every
// format-level check, which is what internalising them prevents -- so the two
// questions consumers actually had get purpose-built answers instead of a
// parsing kit.

// VerifyPassword reports whether password matches the check value an
// encrypted archive embeds, without decrypting any content.
//
// verified is meaningful only when hasCheckValue is true. RAR5 records a
// check value optionally, and an archive that carries none cannot be tested
// this way at all: hasCheckValue is false, verified is false, and the only
// way to learn whether the password is right is to decode a member and see
// whether its checksum holds. Treating a bare verified==false as "wrong
// password" would reject every archive written without one.
//
// A false in both return values with a nil error also covers the ordinary
// cases of an unencrypted archive and an archive whose members are not
// encrypted -- there is nothing to verify, which is not the same as a
// verification that failed.
//
// The scan stops at the first thing that can answer: an archive-level
// encryption header (whole-archive encryption, headers included), or the
// first ENCRYPTED file or service header. Payloads are skipped, never read.
//
// Unencrypted members do not end the scan. RAR5 encrypts per member, so an
// archive can hold both kinds, and the first member being unencrypted says
// nothing about the rest. That means a fully unencrypted archive is scanned
// to its end header before reporting there is nothing to verify -- paying a
// walk over block headers to avoid answering from the first member alone.
func VerifyPassword(r io.Reader, password string) (verified, hasCheckValue bool, err error) {
	if err := readSignature(r); err != nil {
		return false, false, err
	}
	for {
		h, err := readBlockHeader(r)
		if err != nil {
			// Running out of blocks is NOT "nothing to verify". An
			// unencrypted archive answers at its first file header and an
			// empty one at its end header, so neither reaches here: a stream
			// that does has been cut before it said anything. Reporting that
			// as "no password needed" is the same class of mistake as
			// reporting a clean EOF for a truncated member.
			if errors.Is(err, io.EOF) {
				return false, false, fmt.Errorf(
					"%w: archive ended before any header that could be verified",
					io.ErrUnexpectedEOF)
			}
			return false, false, err
		}

		switch h.Type {
		case headerTypeEncryption:
			ch, err := parseCryptHeader(h)
			if err != nil {
				return false, false, err
			}
			return verifyCryptHeaderPassword(ch, password)

		case headerTypeFile, headerTypeService:
			fh, err := parseFileHeader(h)
			if err != nil {
				return false, false, err
			}
			if fh.Encrypted {
				return verifyFileHeaderPassword(fh, password)
			}
			// An unencrypted member is not the answer, only this member's
			// answer. RAR5 encrypts per member, so an archive can hold both
			// -- `rar a x.rar plain` then `rar a -p x.rar secret` produces
			// exactly that, and unrar lists the second with a leading '*'.
			// Stopping here reported "nothing to verify" for an archive
			// whose next member carried the check value, which is a wrong
			// answer rather than a missing one.
			if err := skipPayload(r, h); err != nil {
				return false, false, err
			}

		case headerTypeEnd:
			// Nothing behind the end header belongs to the archive.
			return false, false, nil

		default:
			if err := skipPayload(r, h); err != nil {
				return false, false, err
			}
		}
	}
}

// VolumeNumber reports where r sits within its multi-volume set.
//
// index is 0-based. RAR5 omits the volume-number field on the first volume of
// a set, which is reported here as index 0 rather than as an absence, so a
// caller can order a set without special-casing its first member.
//
// multiVolume is false for a single, unsplit archive, and index is then
// always 0.
//
// This exists to name a volume whose on-disk filename carries no clue --
// downloaded parts routinely arrive with the numbering stripped -- and the
// archive header is the only place the number survives.
func VolumeNumber(r io.Reader) (index int, multiVolume bool, err error) {
	if err := readSignature(r); err != nil {
		return 0, false, err
	}
	for {
		h, err := readBlockHeader(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, false, fmt.Errorf(
					"%w: archive ended before its main header", io.ErrUnexpectedEOF)
			}
			return 0, false, err
		}

		switch h.Type {
		case headerTypeArchive:
			ah, err := parseArchiveHeader(h)
			if err != nil {
				return 0, false, fmt.Errorf("%w: %w", ErrCorruptArchiveHeader, err)
			}
			if !ah.MultiVolume {
				return 0, false, nil
			}
			// A negative VolumeNumber is how the parser reports the field's
			// absence, which RAR5 uses for the first volume of a set.
			if ah.VolumeNumber < 0 {
				return 0, true, nil
			}
			return ah.VolumeNumber, true, nil

		// Scanned for rather than required in first position. A
		// header-encrypted archive puts its encryption header ahead of the
		// main one, and requiring position rather than type would report
		// those as corrupt. Reaching a file header means there was no main
		// header to find.
		case headerTypeFile, headerTypeService, headerTypeEnd:
			return 0, false, fmt.Errorf(
				"%w: no main archive header before the first member",
				ErrCorruptArchiveHeader)

		default:
			if err := skipPayload(r, h); err != nil {
				return 0, false, err
			}
		}
	}
}

// skipPayload advances r past a block's declared payload.
//
// Both entry points above walk blocks without a volume to do it for them, and
// a block whose payload is left unread puts the next readBlockHeader call on
// content rather than on a header -- the same failure volume.next() exists to
// prevent inside the traversal.
func skipPayload(r io.Reader, h *blockHeader) error {
	if h.DataSize <= 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, r, h.DataSize); err != nil {
		return fmt.Errorf("%w: skipping a %d byte payload: %w",
			ErrCorruptBlockHeader, h.DataSize, err)
	}
	return nil
}
