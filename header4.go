package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"
	"unicode/utf16"
)

// RAR 1.5-4.x block types and flags, from unrar's headers.hpp.
const (
	rar4BlockMain    = 0x73
	rar4BlockFile    = 0x74
	rar4BlockService = 0x7a
	rar4BlockEnd     = 0x7b

	rar4LongBlock = 0x8000 // ADD_SIZE follows the base header

	rar4MainVolume   = 0x0001
	rar4MainComment  = 0x0002
	rar4MainSolid    = 0x0008
	rar4MainPassword = 0x0080

	rar4FileSplitBefore = 0x0001
	rar4FileSplitAfter  = 0x0002
	rar4FilePassword    = 0x0004
	rar4FileComment     = 0x0008
	rar4FileSolid       = 0x0010
	rar4FileWindowMask  = 0x00e0
	rar4FileDirectory   = 0x00e0
	rar4FileLarge       = 0x0100
	rar4FileUnicode     = 0x0200
	rar4FileSalt        = 0x0400
	rar4FileExtTime     = 0x1000
)

// rar4LargeEnd is where the rar4FileLarge fields, HIGH_PACK_SIZE and
// HIGH_UNP_SIZE, end in a file or service header body: after its 25 fixed
// bytes. A header with the flag and fewer bytes is corrupt, whichever field it
// cuts.
const rar4LargeEnd = 25 + 8

// readBlockHeader4 reads one RAR 1.5-4.x block header and returns it in the
// shape the traversal reads RAR5 headers in: Type mapped onto the RAR5 header
// types, Payload the header bytes after the 7-byte base, and DataSize the
// bytes that follow the header. A type with no RAR5 counterpart comes back as
// 0x100|type, outside every RAR5 type, so it is skipped by its DataSize.
//
// DataSize of a file or service block is one count, PACK_SIZE | HIGH_PACK_SIZE
// << 32, and parseFileHeader4 takes PackedSize from it rather than reading the
// two fields again.
func readBlockHeader4(r io.Reader) (*blockHeader, error) {
	var base [7]byte
	if _, err := io.ReadFull(r, base[:]); err != nil {
		return nil, err // io.EOF only when the volume ends on a block boundary
	}
	le := binary.LittleEndian
	crc := le.Uint16(base[0:])
	typ := base[2]
	flags := le.Uint16(base[3:])
	size := int(le.Uint16(base[5:]))
	if size < len(base) {
		return nil, ErrCorruptBlockHeader
	}

	// Named before the CRC is checked: unrar does not CRC-check some of the
	// RAR 2.x blocks, and an embedded comment's CRC covers only part of its
	// header, so a mismatch on either would call a valid archive damaged.
	if typ >= 0x75 && typ <= 0x79 {
		return nil, fmt.Errorf("%w: RAR 2.x block type %#x", ErrUnsupportedFormat, typ)
	}
	if (typ == rar4BlockMain && flags&rar4MainComment != 0) ||
		(typ == rar4BlockFile && flags&rar4FileComment != 0) {
		return nil, fmt.Errorf("%w: RAR 2.x comment embedded in a header", ErrUnsupportedFormat)
	}

	// HEAD_CRC covers type through the end of the header.
	buf := make([]byte, size-2)
	copy(buf, base[2:])
	if _, err := io.ReadFull(r, buf[5:]); err != nil {
		return nil, unexpectedEOF(err)
	}
	if crc != uint16(crc32.ChecksumIEEE(buf)) {
		return nil, ErrBadHeaderCRC
	}

	body := buf[5:]
	h := &blockHeader{Flags: uint64(flags), Payload: body, rar4: true}
	switch typ {
	case rar4BlockFile, rar4BlockService:
		if len(body) < 4 {
			return nil, ErrCorruptBlockHeader
		}
		var high uint32
		if flags&rar4FileLarge != 0 {
			if len(body) < rar4LargeEnd {
				return nil, ErrCorruptBlockHeader
			}
			high = le.Uint32(body[25:])
		}
		h.DataSize = int64(le.Uint32(body)) | int64(high)<<32
	default:
		if flags&rar4LongBlock != 0 {
			if len(body) < 4 {
				return nil, ErrCorruptBlockHeader
			}
			h.DataSize = int64(le.Uint32(body))
		}
	}
	if h.DataSize < 0 {
		return nil, ErrCorruptBlockHeader
	}

	switch typ {
	case rar4BlockMain:
		h.Type = headerTypeArchive
	case rar4BlockFile:
		h.Type = headerTypeFile
	case rar4BlockService:
		h.Type = headerTypeService
	case rar4BlockEnd:
		h.Type = headerTypeEnd
	default:
		h.Type = 0x100 | uint64(typ)
	}
	return h, nil
}

// parseArchiveHeader4 decodes a RAR 1.5-4.x main header. Volume numbers live
// in the end header in this format, so VolumeNumber is always -1.
func parseArchiveHeader4(h *blockHeader) (*archiveHeader, error) {
	if h.Type != headerTypeArchive {
		return nil, ErrBadBlockHeader
	}
	if h.Flags&rar4MainPassword != 0 {
		return nil, fmt.Errorf("%w: RAR 1.5-4.x archive with encrypted headers", ErrUnsupportedFormat)
	}
	return &archiveHeader{
		MultiVolume:  h.Flags&rar4MainVolume != 0,
		Solid:        h.Flags&rar4MainSolid != 0,
		VolumeNumber: -1,
	}, nil
}

// parseFileHeader4 decodes a RAR 1.5-4.x file or service header under
// parseFileHeader's contract: a failure before the name is decoded returns a
// nil header, and one after returns the header with the error so the member
// can be refused by name. Those later errors, in priority order:
// ErrUnpSizeUnknown, ErrCorruptFileHeader for a negative size, then
// ErrCorruptFileHeader for a method byte outside 0x30-0x35 or a salt or
// extended time cut short.
//
// PackedSize is h.DataSize, the count the traversal skips by, so the two
// cannot disagree. DictSize stays 0: a RAR4 window is not this library's to
// size. LinkType stays LinkNone, because a RAR4 symlink's target is its
// payload; readLinkTarget4 reads it.
func parseFileHeader4(h *blockHeader) (*FileHeader, error) {
	if h.Type != headerTypeFile && h.Type != headerTypeService {
		return nil, ErrBadBlockHeader
	}
	flags := uint16(h.Flags)
	body := h.Payload
	fixed := 25
	if flags&rar4FileLarge != 0 {
		fixed = rar4LargeEnd
	}
	if len(body) < fixed {
		return nil, ErrCorruptFileHeader
	}
	le := binary.LittleEndian
	nameLen := int(le.Uint16(body[19:]))
	if len(body) < fixed+nameLen {
		return nil, ErrCorruptFileHeader
	}

	unpLow, unpHigh := le.Uint32(body[4:]), uint32(0)
	if flags&rar4FileLarge != 0 {
		unpHigh = le.Uint32(body[29:])
	}
	unpSizeUnknown := unpLow == 0xffffffff && (flags&rar4FileLarge == 0 || unpHigh == 0xffffffff)

	attr := le.Uint32(body[21:])
	ver := body[17]
	fh := &FileHeader{
		PackedSize:    h.DataSize,
		UnpackedSize:  int64(unpLow) | int64(unpHigh)<<32,
		IsDir:         flags&rar4FileWindowMask == rar4FileDirectory || (ver < 20 && attr&0x10 != 0),
		Solid:         flags&rar4FileSolid != 0,
		FirstBlock:    flags&rar4FileSplitBefore == 0,
		LastBlock:     flags&rar4FileSplitAfter == 0,
		Encrypted:     flags&rar4FilePassword != 0,
		UnpackVersion: int(ver),
		CRC32:         le.Uint32(body[9:]),
		HasCRC32:      true,
		HostOS:        hostOS4(body[8]),
		Attributes:    uint64(attr),
	}
	raw := body[fixed : fixed+nameLen]
	if h.Type == headerTypeService {
		fh.Name = sanitizePath(strings.ToValidUTF8(string(raw), "�"))
	} else {
		fh.Name = decodeName4(flags, raw)
	}

	if unpSizeUnknown {
		return fh, ErrUnpSizeUnknown
	}
	if fh.UnpackedSize < 0 {
		return fh, ErrCorruptFileHeader
	}
	method := body[18]
	if method < 0x30 || method > 0x35 {
		return fh, fmt.Errorf("%w: file %q: unknown method byte %#x", ErrCorruptFileHeader, fh.Name, method)
	}
	fh.Method = int(method - 0x30)

	fh.ModificationTime = dosTime(le.Uint32(body[13:]))
	if h.Type == headerTypeService {
		// A service header's optional data sits between its name and the
		// salt, unsized, and nothing here reads its time.
		return fh, nil
	}
	tail := body[fixed+nameLen:]
	if flags&rar4FileSalt != 0 {
		if len(tail) < 8 {
			return fh, fmt.Errorf("%w: file %q: salt cut short", ErrCorruptFileHeader, fh.Name)
		}
		tail = tail[8:]
	}
	if flags&rar4FileExtTime != 0 {
		mtime, err := extMtime4(fh.ModificationTime, tail)
		if err != nil {
			return fh, fmt.Errorf("%w: file %q: %v", ErrCorruptFileHeader, fh.Name, err)
		}
		fh.ModificationTime = mtime
	}
	return fh, nil
}

// extMtime4 refines a DOS mtime from the extended-time field: a 16-bit flags
// word whose top four bits are mtime's mode -- 8 present, 4 add one second,
// the low two a count of 100 ns remainder bytes, most significant last. The
// other three times that may follow are not decoded. unrar arcread.cpp.
func extMtime4(t time.Time, tail []byte) (time.Time, error) {
	if len(tail) < 2 {
		return t, errors.New("extended time cut short")
	}
	mode := binary.LittleEndian.Uint16(tail) >> 12
	if mode&8 == 0 {
		return t, nil
	}
	if mode&4 != 0 {
		t = t.Add(time.Second)
	}
	n := int(mode & 3)
	if len(tail) < 2+n {
		return t, errors.New("extended time cut short")
	}
	var rem uint32
	for j := range n {
		rem |= uint32(tail[2+j]) << ((j + 3 - n) * 8)
	}
	return t.Add(time.Duration(rem) * 100), nil
}

// decodeName4 turns a RAR4 file name into a sanitized, valid UTF-8 path.
//
// With rar4FileUnicode and a NUL, the bytes after the NUL are unrar's
// compressed UTF-16 encoding of the name (EncodeFileName::Decode, ported in
// decodeEncName4). With the flag and no NUL the name is UTF-8. Without the
// flag it is in the archiving host's OEM code page, which is not decoded:
// bytes that are not UTF-8 become U+FFFD.
func decodeName4(flags uint16, raw []byte) string {
	s := ""
	if flags&rar4FileUnicode != 0 {
		if before, after, ok := bytes.Cut(raw, []byte{0}); !ok {
			s = string(raw)
		} else if w := decodeEncName4(raw, after); len(w) > 0 {
			s = string(utf16.Decode(w))
		} else {
			s = string(before)
		}
	} else {
		s = string(raw)
	}
	return sanitizePath(strings.ToValidUTF8(s, "�"))
}

// decodeEncName4 is unrar's EncodeFileName::Decode. name is the whole raw
// name field, not only the part before the NUL: a copy run indexes it by
// output position and may reach past the NUL, as unrar's does. Every index is
// bounded, so a malformed encoding ends the name early instead of panicking.
func decodeEncName4(name, enc []byte) []uint16 {
	var out []uint16
	pos := 0
	if len(enc) == 0 {
		return nil
	}
	high := uint16(enc[pos])
	pos++
	var flags byte
	bits := 0
	for pos < len(enc) {
		if bits == 0 {
			flags = enc[pos]
			pos++
			bits = 8
		}
		switch flags >> 6 {
		case 0:
			if pos >= len(enc) {
				break
			}
			out = append(out, uint16(enc[pos]))
			pos++
		case 1:
			if pos >= len(enc) {
				break
			}
			out = append(out, uint16(enc[pos])|high<<8)
			pos++
		case 2:
			if pos+1 >= len(enc) {
				break
			}
			out = append(out, uint16(enc[pos])|uint16(enc[pos+1])<<8)
			pos += 2
		case 3:
			if pos >= len(enc) {
				break
			}
			length := int(enc[pos])
			pos++
			if length&0x80 != 0 {
				if pos >= len(enc) {
					break
				}
				corr := enc[pos]
				pos++
				for n := length&0x7f + 2; n > 0 && len(out) < len(name); n-- {
					out = append(out, uint16(name[len(out)]+corr)|high<<8)
				}
			} else {
				for n := length + 2; n > 0 && len(out) < len(name); n-- {
					out = append(out, uint16(name[len(out)]))
				}
			}
		}
		flags <<= 2
		bits -= 2
	}
	return out
}

// hostOS4 maps a RAR4 HOST_OS byte onto FileHeader.HostOS: Unix and BeOS
// (3, 5) are Unix, 1; everything else, including values no RAR wrote, is 0.
// A member is never refused for its host.
func hostOS4(b byte) uint64 {
	if b == 3 || b == 5 {
		return 1
	}
	return 0
}

// dosTime decodes a DOS date and time, which carries no zone; unrar reads it
// as local time.
func dosTime(v uint32) time.Time {
	return time.Date(int(v>>25)+1980, time.Month(v>>21&0xf), int(v>>16&0x1f),
		int(v>>11&0x1f), int(v>>5&0x3f), int(v&0x1f)*2, 0, time.Local)
}

// maxLinkTarget4 bounds a RAR4 symlink target: Linux PATH_MAX.
const maxLinkTarget4 = 4096

// isSymlink4 reports a RAR4 Unix symlink: a Unix-host member whose mode is
// S_IFLNK. Its target is its payload.
func isSymlink4(fh *FileHeader) bool {
	return fh.HostOS == 1 && fh.Attributes&0xf000 == 0xa000
}

// readLinkTarget4 reads a RAR4 symlink's target from its stored payload and
// makes fh a LinkUnixSymlink to it. The target is kept exactly as stored, per
// FileHeader.LinkTarget. On any refusal fh is left an ordinary header, since a
// link always carries a non-empty target.
func readLinkTarget4(fh *FileHeader, src io.Reader) error {
	if !fh.FirstBlock || !fh.LastBlock {
		return fmt.Errorf("%w: split symlink %q", ErrCorruptFileHeader, fh.Name)
	}
	if fh.PackedSize != fh.UnpackedSize || fh.PackedSize <= 0 || fh.PackedSize > maxLinkTarget4 {
		return fmt.Errorf("%w: symlink %q declares a %d-byte target in %d bytes",
			ErrCorruptFileHeader, fh.Name, fh.UnpackedSize, fh.PackedSize)
	}
	target := make([]byte, fh.PackedSize)
	if _, err := io.ReadFull(src, target); err != nil {
		return fmt.Errorf("%w: symlink %q: %v", ErrTruncatedFile, fh.Name, err)
	}
	if crc32.ChecksumIEEE(target) != fh.CRC32 {
		return fmt.Errorf("%w: symlink %q", ErrCRCMismatch, fh.Name)
	}
	if bytes.IndexByte(target, 0) >= 0 {
		return fmt.Errorf("%w: symlink %q target contains NUL", ErrCorruptFileHeader, fh.Name)
	}
	fh.LinkType = LinkUnixSymlink
	fh.LinkTarget = string(target)
	return nil
}
