package rarengine

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"time"
)

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
	if flags&0x8000 > 0 {
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
	if flags&0x8000 > 0 {
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
	if h.Flags&0x0100 > 0 {
		if len(payload) < offset+8 {
			return nil, ErrCorruptFileHeader
		}
		highPack = binary.LittleEndian.Uint32(payload[offset : offset+4])
		highUnp = binary.LittleEndian.Uint32(payload[offset+4 : offset+8])
		offset += 8
	}

	finalPackSize := h.DataSize | (int64(highPack) << 32)
	finalUnpSize := int64(unpSize) | (int64(highUnp) << 32)

	if len(payload) < offset+int(nameSize) {
		return nil, ErrCorruptFileHeader
	}
	rawName := string(payload[offset : offset+int(nameSize)])
	offset += int(nameSize)

	var salt []byte
	if h.Flags&0x0400 > 0 {
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
		Name:             sanitizePath(rawName),
		IsDir:            isDir,
		PackedSize:       finalPackSize,
		UnpackedSize:     finalUnpSize,
		Solid:            (h.Flags & 0x0010) > 0,
		FirstBlock:       (h.Flags & 0x0001) == 0,
		LastBlock:        (h.Flags & 0x0002) == 0,
		Method:           finalMethod,
		CRC32:            fileCrc,
		HasCRC32:         true,
		Encrypted:        (h.Flags & 0x0400) > 0,
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
