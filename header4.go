package rarengine

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
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
