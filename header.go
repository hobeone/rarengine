package rarengine

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

var (
	ErrBadBlockHeader       = errors.New("rarengine: bad block header")
	ErrBadHeaderCRC         = errors.New("rarengine: bad header CRC")
	ErrCorruptBlockHeader   = errors.New("rarengine: corrupt block header")
	ErrCorruptFileHeader    = errors.New("rarengine: corrupt file header")
	ErrUnknownEncryptMethod = errors.New("rarengine: unknown encryption method")
	ErrCorruptEncryptData   = errors.New("rarengine: corrupt encryption record")
)

const (
	maxHeaderSize = 2097151 // 2MB - 1 byte, max valid 3-byte vint

	// Header types
	HeaderTypeArchive    = 1
	HeaderTypeFile       = 2
	HeaderTypeService    = 3
	HeaderTypeEncryption = 4
	HeaderTypeEnd        = 5

	// General Header Flags
	HeaderFlagHasExtra     = 0x0001
	HeaderFlagHasData      = 0x0002
	HeaderFlagDataNotFirst = 0x0008
	HeaderFlagDataNotLast  = 0x0010

	// Main Archive Header Flags
	ArcFlagMultiVol = 0x0001
	ArcFlagVolNum   = 0x0002
	ArcFlagSolid    = 0x0004

	// File Header Flags
	FileFlagIsDir          = 0x0001
	FileFlagHasUnixMtime   = 0x0002
	FileFlagHasCRC32       = 0x0004
	FileFlagUnpSizeUnknown = 0x0008

	// File Compression Flags
	FileCompSolid = 0x00000040

	// File Encryption Extra Flags
	FileEncCheckPresent = 0x0001
	FileEncUseMac       = 0x0002
)

// BlockHeader represents a generic RAR5 block header.
type BlockHeader struct {
	Type     uint64
	Flags    uint64
	DataSize int64
	Payload  []byte
	Extra    []ExtraRecord
}

// ExtraRecord represents metadata parsed from header extra area.
type ExtraRecord struct {
	Type uint64
	Data []byte
}

// ArchiveHeader represents a parsed main archive header.
type ArchiveHeader struct {
	MultiVolume  bool
	Solid        bool
	VolumeNumber int
}

// FileHeader represents a parsed file header inside the archive.
type FileHeader struct {
	Name             string
	IsDir            bool
	PackedSize       int64
	UnpackedSize     int64
	Solid            bool
	FirstBlock       bool // true if this is the first block/volume-part of the file
	LastBlock        bool // true if this is the last block/volume-part of the file
	Method           int  // compression method: 0 = store, 1..5 = compress
	DictSize         int64
	CRC32            uint32
	HasCRC32         bool
	HasBlake2sp      bool
	Blake2sp         []byte // 32-byte BLAKE2sp hash
	Encrypted        bool
	KdfCount         int
	Salt             []byte
	IV               []byte
	UseMac           bool
	EncCheck         []byte
	ModificationTime time.Time
	HostOS           uint64
	Attributes       uint64
}

// Mode returns the Go fs.FileMode mapped from the HostOS and Attributes values.
func (fh *FileHeader) Mode() fs.FileMode {
	var m fs.FileMode
	if fh.IsDir {
		m |= fs.ModeDir
	}
	if fh.HostOS == 1 { // Unix
		m |= fs.FileMode(fh.Attributes & 0o7777)
	} else { // Windows / default
		if fh.IsDir {
			m |= 0o755
		} else {
			if fh.Attributes&0x01 > 0 { // Read-only
				m |= 0o444
			} else {
				m |= 0o644
			}
		}
	}
	return m
}

// ReadBlockHeader reads and validates a RAR5 block header from the stream.
func ReadBlockHeader(r io.Reader) (*BlockHeader, error) {
	var sizeBuf [7]byte
	_, err := io.ReadFull(r, sizeBuf[:])
	if err != nil {
		return nil, err
	}

	crc := binary.LittleEndian.Uint32(sizeBuf[0:4])

	// Decode the header size vint starting at sizeBuf[4:]
	sizeV, n, err := DecodeVint(sizeBuf[4:])
	if err != nil {
		return nil, err
	}
	if sizeV > maxHeaderSize {
		return nil, ErrBadBlockHeader
	}
	size := int(sizeV)

	// bufSize is the size of the rest of the header payload covered by CRC
	bufSize := size + n
	if bufSize < n {
		return nil, ErrBadBlockHeader
	}

	buf := make([]byte, bufSize)
	// Copy the size vint and any remaining bytes of sizeBuf[4:] that we read
	copy(buf, sizeBuf[4:])

	// Read the remaining bytes to complete the header
	if bufSize > 3 {
		_, err = io.ReadFull(r, buf[3:])
		if err != nil {
			return nil, err
		}
	}

	// Validate CRC32
	hash := crc32.NewIEEE()
	_, _ = hash.Write(buf)
	if crc != hash.Sum32() {
		return nil, ErrBadHeaderCRC
	}

	return parseBlockHeaderFields(buf, n)
}

// parseBlockHeaderFields decodes type, flags, payload, and extra records
// from a header's already CRC-validated byte buffer (everything after the
// CRC32 field). n is the byte length of the leading size vint within buf,
// shared by both ReadBlockHeader's plaintext path and headerDecrypter's
// decrypted-header path so the two don't duplicate this parsing logic.
func parseBlockHeaderFields(buf []byte, n int) (*BlockHeader, error) {
	payload := buf[n:]

	hType, nType, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nType:]

	flags, nFlags, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	h := &BlockHeader{
		Type:  hType,
		Flags: flags,
	}

	var extraSize int
	if flags&HeaderFlagHasExtra > 0 {
		exSizeV, nEx, err := DecodeVint(payload)
		if err != nil {
			return nil, err
		}
		extraSize = int(exSizeV)
		payload = payload[nEx:]
	}

	if flags&HeaderFlagHasData > 0 {
		dtSizeV, nDt, err := DecodeVint(payload)
		if err != nil {
			return nil, err
		}
		h.DataSize = int64(dtSizeV)
		payload = payload[nDt:]
	}

	if len(payload) < extraSize {
		return nil, ErrCorruptBlockHeader
	}

	h.Payload = payload[:len(payload)-extraSize]

	extraPayload := payload[len(payload)-extraSize:]
	for len(extraPayload) > 0 {
		exRecSizeV, nExRecSize, err := DecodeVint(extraPayload)
		if err != nil {
			return nil, err
		}
		exRecSize := int(exRecSizeV)
		extraPayload = extraPayload[nExRecSize:]
		if len(extraPayload) < exRecSize {
			return nil, ErrCorruptBlockHeader
		}

		recData := extraPayload[:exRecSize]
		extraPayload = extraPayload[exRecSize:]

		fType, nFType, err := DecodeVint(recData)
		if err != nil {
			return nil, err
		}
		h.Extra = append(h.Extra, ExtraRecord{
			Type: fType,
			Data: recData[nFType:],
		})
	}

	return h, nil
}

// ParseArchiveHeader decodes the main archive header details.
func ParseArchiveHeader(h *BlockHeader) (*ArchiveHeader, error) {
	if h.Type != HeaderTypeArchive {
		return nil, ErrBadBlockHeader
	}
	payload := h.Payload

	flags, nFlags, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	ah := &ArchiveHeader{
		MultiVolume:  flags&ArcFlagMultiVol > 0,
		Solid:        flags&ArcFlagSolid > 0,
		VolumeNumber: -1,
	}

	if flags&ArcFlagVolNum > 0 {
		volNum, _, err := DecodeVint(payload)
		if err != nil {
			return nil, err
		}
		ah.VolumeNumber = int(volNum)
	}

	return ah, nil
}

// parseEncryptionRecord decodes RAR5 encryption extra record details.
func parseEncryptionRecord(fh *FileHeader, b []byte) error {
	ver, nVer, err := DecodeVint(b)
	if err != nil {
		return err
	}
	if ver != 0 {
		return ErrUnknownEncryptMethod
	}
	b = b[nVer:]

	encFlags, nEnc, err := DecodeVint(b)
	if err != nil {
		return err
	}
	b = b[nEnc:]

	if len(b) < 33 {
		return ErrCorruptEncryptData
	}
	fh.Encrypted = true
	fh.KdfCount = int(b[0])
	fh.Salt = append([]byte(nil), b[1:17]...)
	fh.IV = append([]byte(nil), b[17:33]...)
	b = b[33:]

	if encFlags&FileEncCheckPresent > 0 {
		if len(b) < 12 {
			return ErrCorruptEncryptData
		}
		fh.EncCheck = append([]byte(nil), b[:12]...)
	}
	fh.UseMac = encFlags&FileEncUseMac > 0
	return nil
}

// parseHashRecord decodes RAR5 blake2sp file hash extra record details.
func parseHashRecord(fh *FileHeader, b []byte) error {
	hashType, nHash, err := DecodeVint(b)
	if err != nil {
		return err
	}
	b = b[nHash:]
	if hashType == 0 && len(b) >= sha256.Size {
		fh.HasBlake2sp = true
		fh.Blake2sp = append([]byte(nil), b[:sha256.Size]...)
	}
	return nil
}

// parseExtraRecords iterates over extra records and parses encryption or file hash blocks.
func parseExtraRecords(fh *FileHeader, extra []ExtraRecord) error {
	for _, e := range extra {
		switch e.Type {
		case 1: // Encryption
			if err := parseEncryptionRecord(fh, e.Data); err != nil {
				return err
			}
		case 2: // File hash (Blake2sp)
			if err := parseHashRecord(fh, e.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseFileHeader decodes the file header details from a block header.
func ParseFileHeader(h *BlockHeader) (*FileHeader, error) {
	if h.Type != HeaderTypeFile && h.Type != HeaderTypeService {
		return nil, ErrBadBlockHeader
	}
	payload := h.Payload

	flags, nFlags, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	fh := &FileHeader{
		IsDir:      flags&FileFlagIsDir > 0,
		FirstBlock: h.Flags&HeaderFlagDataNotFirst == 0,
		LastBlock:  h.Flags&HeaderFlagDataNotLast == 0,
		PackedSize: h.DataSize,
	}

	unpackedSize, nUnp, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	fh.UnpackedSize = int64(unpackedSize)
	payload = payload[nUnp:]

	attrs, nAttrs, err := DecodeVint(payload) // Attributes
	if err != nil {
		return nil, err
	}
	fh.Attributes = attrs
	payload = payload[nAttrs:]

	if flags&FileFlagHasUnixMtime > 0 {
		if len(payload) < 4 {
			return nil, ErrCorruptFileHeader
		}
		mtime := binary.LittleEndian.Uint32(payload[0:4])
		fh.ModificationTime = time.Unix(int64(mtime), 0)
		payload = payload[4:]
	}

	if flags&FileFlagHasCRC32 > 0 {
		if len(payload) < 4 {
			return nil, ErrCorruptFileHeader
		}
		fh.CRC32 = binary.LittleEndian.Uint32(payload[0:4])
		fh.HasCRC32 = true
		payload = payload[4:]
	}

	compFlags, nComp, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	fh.Solid = compFlags&FileCompSolid > 0
	fh.Method = int((compFlags >> 7) & 7)
	payload = payload[nComp:]

	hostOS, nOS, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	fh.HostOS = hostOS
	payload = payload[nOS:]

	nameLen, nName, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nName:]

	if len(payload) < int(nameLen) {
		return nil, ErrCorruptFileHeader
	}
	fh.Name = sanitizePath(string(payload[:nameLen]))

	// Parse optional extra records
	if err := parseExtraRecords(fh, h.Extra); err != nil {
		return nil, err
	}

	return fh, nil
}

func sanitizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	cleaned := path.Clean(p)
	if path.IsAbs(cleaned) {
		cleaned = cleaned[1:]
	}
	parts := strings.Split(cleaned, "/")
	var res []string
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		res = append(res, part)
	}
	return path.Join(res...)
}
