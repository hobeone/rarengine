package rarengine

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"time"
)

// RAR3 file header flags (LHD_*), named because these values are not
// checkable by eye against a spec and one of them was previously read wrong.
//
// lhdPassword and lhdSalt are adjacent in meaning but far apart in value, and
// conflating them is the specific mistake this block exists to prevent:
// lhdSalt only says eight salt bytes follow the name, which is a statement
// about the header's layout, while lhdPassword is what says the member is
// encrypted. Real RAR 3.x encryption sets both, so the difference is invisible
// on any honest archive and shows up only on a crafted one.
const (
	lhdSplitBefore = 0x0001
	lhdSplitAfter  = 0x0002
	lhdPassword    = 0x0004
	lhdSolid       = 0x0010
	lhdLarge       = 0x0100
	lhdSalt        = 0x0400
)

// mhdPassword marks a RAR3 archive whose block headers are themselves
// encrypted, in the main (0x73) header's flags.
const mhdPassword = 0x0080

// longBlock says a four-byte ADD_SIZE follows the base header, giving the block
// a payload in the stream after its header. It is read for every block type
// with no restriction on which, which is why the dispatchers must account for a
// declared payload on every block rather than only on file headers.
const longBlock = 0x8000

// RAR3 block types. Named because the dispatchers switch on them and a sweep
// test enumerates them: a type space written as bare hex in a switch cannot be
// iterated, so nothing can assert that every type accounts for its payload.
//
// mhdFirstVolume shares the 0x0100 bit with lhdLarge and means something
// entirely different -- it is why a "does this block declare a large payload"
// test must be scoped to the block types that actually carry file-header
// layout, rather than applied to any block whose flags happen to set that bit.
const (
	rar3BlockMark       = 0x72
	rar3BlockMain       = 0x73
	rar3BlockFile       = 0x74
	rar3BlockComment    = 0x75
	rar3BlockAV         = 0x76
	rar3BlockOldSub     = 0x77
	rar3BlockProtect    = 0x78
	rar3BlockSign       = 0x79
	rar3BlockNewSub     = 0x7a
	rar3BlockTerminator = 0x7b

	mhdFirstVolume = 0x0100
)

// rar3UsesFileLayout reports whether a block type carries the file-header
// layout, and therefore may carry lhdLarge and a high half to its packed size.
//
// The file type itself is excluded: its dispatcher case parses the header and
// gets the composed size from ParseRAR3FileHeader. What this names is the
// subblock types, which no dispatcher parses -- their payload is discarded by
// declared length alone, and that length is only the low 32 bits.
func rar3UsesFileLayout(blockType uint64) bool {
	return blockType == rar3BlockOldSub || blockType == rar3BlockNewSub
}

// rar3ClaimsEncryption reports whether a RAR3 file header claims encryption by
// either of the two bits that can say so.
//
// Either alone is a claim: lhdPassword says the member is encrypted, lhdSalt
// says a salt accompanies it, and a salt is meaningless on anything else. Real
// RAR 3.x sets both; a crafted archive need not, so both are tested.
//
// One predicate rather than the condition written twice, because it is checked
// at two sites -- file admission and every volume advance -- whose responses
// differ but whose question does not. Narrowing what counts as a claim should
// take one edit, not two kept in step by hand.
func rar3ClaimsEncryption(fh *FileHeader) bool {
	return fh.Encrypted || len(fh.Salt) > 0
}

// ReadRAR3BlockHeader reads and validates a RAR3 block header.
func ReadRAR3BlockHeader(r io.Reader) (*BlockHeader, error) {
	var baseBuf [7]byte
	_, err := io.ReadFull(r, baseBuf[:])
	if err != nil {
		return nil, err
	}

	crc := binary.LittleEndian.Uint16(baseBuf[0:2])
	hType := baseBuf[2]
	flags := binary.LittleEndian.Uint16(baseBuf[3:5])
	hSize := binary.LittleEndian.Uint16(baseBuf[5:7])

	if hSize < 7 {
		return nil, ErrBadBlockHeader
	}

	var addSize uint32
	var payloadSize int
	if flags&longBlock > 0 {
		if hSize < 11 {
			return nil, ErrBadBlockHeader
		}
		var addBuf [4]byte
		_, err = io.ReadFull(r, addBuf[:])
		if err != nil {
			return nil, err
		}
		addSize = binary.LittleEndian.Uint32(addBuf[:])
		payloadSize = int(hSize) - 11
	} else {
		payloadSize = int(hSize) - 7
	}

	payload := make([]byte, payloadSize)
	if payloadSize > 0 {
		_, err = io.ReadFull(r, payload)
		if err != nil {
			return nil, err
		}
	}

	// Validate CRC
	crcBuf := make([]byte, 0, int(hSize)-2)
	crcBuf = append(crcBuf, baseBuf[2:]...)
	if flags&longBlock > 0 {
		var addBuf [4]byte
		binary.LittleEndian.PutUint32(addBuf[:], addSize)
		crcBuf = append(crcBuf, addBuf[:]...)
	}
	crcBuf = append(crcBuf, payload...)

	computedCrc := uint16(crc32.ChecksumIEEE(crcBuf))
	if crc != computedCrc {
		return nil, ErrBadHeaderCRC
	}

	return &BlockHeader{
		Type:     uint64(hType),
		Flags:    uint64(flags),
		DataSize: int64(addSize),
		Payload:  payload,
	}, nil
}

// ParseRAR3FileHeader decodes the file header details from a RAR3 block header.
func ParseRAR3FileHeader(h *BlockHeader) (*FileHeader, error) {
	payload := h.Payload
	if len(payload) < 21 {
		return nil, ErrCorruptFileHeader
	}

	unpSize := binary.LittleEndian.Uint32(payload[0:4])
	hostOS := payload[4]
	fileCrc := binary.LittleEndian.Uint32(payload[5:9])
	fTime := binary.LittleEndian.Uint32(payload[9:13])
	_ = payload[13] // unpVer
	method := payload[14]
	nameSize := binary.LittleEndian.Uint16(payload[15:17])
	attr := binary.LittleEndian.Uint32(payload[17:21])

	offset := 21

	var highPack, highUnp uint32
	if h.Flags&lhdLarge > 0 {
		if len(payload) < offset+8 {
			return nil, ErrCorruptFileHeader
		}
		highPack = binary.LittleEndian.Uint32(payload[offset : offset+4])
		highUnp = binary.LittleEndian.Uint32(payload[offset+4 : offset+8])
		offset += 8
	}

	finalPackSize := h.DataSize | (int64(highPack) << 32)
	finalUnpSize := int64(unpSize) | (int64(highUnp) << 32)

	// The high halves are attacker-supplied, so either size can be given the
	// sign bit. A negative size would pass every "have we produced enough
	// yet" comparison downstream; reject it at the boundary instead.
	if finalPackSize < 0 || finalUnpSize < 0 {
		return nil, ErrCorruptFileHeader
	}

	if len(payload) < offset+int(nameSize) {
		return nil, ErrCorruptFileHeader
	}
	rawName := string(payload[offset : offset+int(nameSize)])
	offset += int(nameSize)

	var salt []byte
	if h.Flags&lhdSalt > 0 {
		if len(payload) < offset+8 {
			return nil, ErrCorruptFileHeader
		}
		salt = append([]byte(nil), payload[offset:offset+8]...)
	}

	mtime := parseDOSTime(fTime)

	var finalMethod int
	if method == 0x30 {
		finalMethod = 0
	} else if method >= 0x31 && method <= 0x35 {
		finalMethod = int(method - 0x30)
	}

	isDir := (attr & 0x10) > 0
	if hostOS == 3 { // Unix
		isDir = (attr & 0o170000) == 0o040000
	}

	fh := &FileHeader{
		Name:         sanitizePath(rawName),
		IsDir:        isDir,
		PackedSize:   finalPackSize,
		UnpackedSize: finalUnpSize,
		Solid:        (h.Flags & lhdSolid) > 0,
		FirstBlock:   (h.Flags & lhdSplitBefore) == 0,
		LastBlock:    (h.Flags & lhdSplitAfter) == 0,
		Method:       finalMethod,
		CRC32:        fileCrc,
		HasCRC32:     true,
		// lhdPassword, not lhdSalt. This field previously carried the salt
		// bit, which says only that eight salt bytes are present -- so a
		// member encrypted without a salt reported Encrypted false and was
		// decoded as though its ciphertext were content.
		Encrypted:        (h.Flags & lhdPassword) > 0,
		Salt:             salt,
		ModificationTime: mtime,
		HostOS:           uint64(hostOS),
		Attributes:       uint64(attr),
	}

	return fh, nil
}

func parseDOSTime(dosTime uint32) time.Time {
	sec := int((dosTime & 0x1f) * 2)
	min := int((dosTime >> 5) & 0x3f)
	hour := int((dosTime >> 11) & 0x1f)
	day := int((dosTime >> 16) & 0x1f)
	month := time.Month((dosTime >> 21) & 0x0f)
	year := int(((dosTime >> 25) & 0x7f) + 1980)

	if month < 1 || month > 12 || day < 1 || day > 31 {
		return time.Time{}
	}

	return time.Date(year, month, day, hour, min, sec, 0, time.Local)
}
