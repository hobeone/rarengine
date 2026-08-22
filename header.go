package rarengine

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"math/bits"
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

	// ErrUnpSizeUnknown is returned for a file whose header declares that its
	// unpacked size is not known (FileFlagUnpSizeUnknown), as produced by
	// streamed archiving such as "rar -si". Decoding relies on the declared
	// size to tell a completed file from a truncated one, so a file that
	// declines to state it is refused rather than decoded on a size that
	// means nothing.
	ErrUnpSizeUnknown = errors.New("rarengine: file header declares an unknown unpacked size")
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
	Name         string
	IsDir        bool
	PackedSize   int64
	UnpackedSize int64
	Solid        bool
	FirstBlock   bool // true if this is the first block/volume-part of the file
	LastBlock    bool // true if this is the last block/volume-part of the file
	Method       int  // compression method: 0 = store, 1..5 = compress
	DictSize     int64
	CRC32        uint32
	HasCRC32     bool
	HasBlake2sp  bool
	Blake2sp     []byte // 32-byte BLAKE2sp hash
	// Encrypted reports that the member's content is encrypted: RAR5's
	// encryption record, or RAR3's LHD_PASSWORD (0x0004). Not RAR3's
	// LHD_SALT (0x0400), which says only that eight salt bytes follow the
	// name -- reading the salt bit as encryption is how an encrypted member
	// carrying no salt came to be decoded as though it were plaintext.
	//
	// Reader.NextEntry only ever traverses RAR5 archives -- openVolume
	// refuses a RAR3 signature outright, before any per-member parsing runs
	// -- so a RAR3-flavoured Encrypted value is observed only by a caller
	// that calls ParseRAR3FileHeader directly for inspection. RAR5 members
	// are decrypted normally by NextEntry and returned with this set.
	Encrypted bool
	KdfCount  int
	// Salt is the PBKDF2 salt for an encrypted member. For RAR3, LHD_SALT and
	// LHD_PASSWORD are each independently a claim of encryption (see
	// Encrypted's comment); a caller that wants full encryption-claim
	// detection across both bits should check Encrypted || len(Salt) > 0.
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
		if h.DataSize < 0 {
			return nil, ErrCorruptBlockHeader
		}
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

// Extra record 3 (file times) flags.
const (
	extraTimeUnix   = 0x0001 // times are unix seconds rather than Windows FILETIME
	extraTimeMtime  = 0x0002
	extraTimeCtime  = 0x0004
	extraTimeAtime  = 0x0008
	extraTimeUnixNS = 0x0010 // a nanosecond field follows for each unix time
)

// filetimeEpochOffset is the number of 100ns ticks between the Windows FILETIME
// epoch (1601-01-01 UTC) and the Unix epoch.
const filetimeEpochOffset = 116444736000000000

// parseTimeRecord decodes the file-times extra record.
//
// The modification time is not read from the file header's own mtime field
// alone: rar only sets FileFlagHasUnixMtime for whole-second times, and
// current versions record the time here instead. Parsing only the flag left
// ModificationTime zero for every archive rar actually produces, which made
// UnpackOptions.IgnoreUnrarDates a no-op -- extracted files never carried
// their archive timestamps in either mode.
//
// Only the modification time is kept, because FileHeader exposes only that.
// The others still have to be stepped over: every present time's seconds are
// stored before any of the nanoseconds, so the mtime nanosecond field sits
// after the ctime and atime seconds rather than next to its own.
func parseTimeRecord(fh *FileHeader, data []byte) error {
	flags, n, err := DecodeVint(data)
	if err != nil {
		return ErrCorruptFileHeader
	}
	data = data[n:]

	// Every declared time is checked for, not just the one kept. A record
	// promising three times and carrying one is malformed however little of
	// it this function goes on to read, and accepting it would let a header
	// declare fields it does not have.
	unix := flags&extraTimeUnix != 0
	present := bits.OnesCount64(flags & (extraTimeMtime | extraTimeCtime | extraTimeAtime))

	need := 8 * present
	if unix {
		need = 4 * present
		if flags&extraTimeUnixNS != 0 {
			need += 4 * present
		}
	}
	if len(data) < need {
		return ErrCorruptFileHeader
	}

	// mtime is stored first when present, so its absence means everything
	// this record carries belongs to a time FileHeader does not expose.
	if flags&extraTimeMtime == 0 {
		return nil
	}

	if !unix {
		ticks := int64(binary.LittleEndian.Uint64(data[:8])) - filetimeEpochOffset
		fh.ModificationTime = time.Unix(ticks/1e7, (ticks%1e7)*100)
		return nil
	}

	sec := int64(binary.LittleEndian.Uint32(data[:4]))

	var nsec int64
	if flags&extraTimeUnixNS != 0 {
		// Every present time's seconds precede all of the nanoseconds, so
		// mtime's nanosecond field sits past the ctime and atime seconds
		// rather than beside its own.
		off := 4 * present
		// Attacker-supplied: a value at or beyond a second would roll the
		// time forward into a different second than the archive recorded.
		if ns := int64(binary.LittleEndian.Uint32(data[off : off+4])); ns < 1e9 {
			nsec = ns
		}
	}

	fh.ModificationTime = time.Unix(sec, nsec)
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
		case 3: // File times
			if err := parseTimeRecord(fh, e.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseFileHeader decodes the file header details from a block header.
func ParseFileHeader(h *BlockHeader) (*FileHeader, error) {
	fh, err := parseFileHeader(h)
	if err != nil {
		return nil, err
	}
	return fh, nil
}

// parseFileHeader is ParseFileHeader's internal form. It is the ONLY function
// in this package permitted to return a non-nil *FileHeader alongside a
// non-nil error: every failure up through the name field means there is no
// identity to report, so those paths return a nil header like any other
// parse failure. Only a failure inside parseExtraRecords, the last step,
// returns the header it built anyway -- by that point the member's name and
// sizes are already decoded, so the caller (Reader.dispatch) can refuse the
// member by name instead of dropping it from the listing with no trace.
func parseFileHeader(h *BlockHeader) (*FileHeader, error) {
	if h.Type != HeaderTypeFile && h.Type != HeaderTypeService {
		return nil, ErrBadBlockHeader
	}
	payload := h.Payload

	flags, nFlags, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	// Captured here, at the point the flag is decoded, but not acted on until
	// the validation block below: the flag itself is decoded identity, not a
	// failure to decode, and the name has not been read yet.
	unpSizeUnknown := flags&FileFlagUnpSizeUnknown > 0

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
	// The vint carries up to 70 bits, so an attacker can set the sign bit of
	// the int64. A negative size would sail past every "have we produced
	// enough yet" comparison downstream, so decoding it here always happens,
	// but rejecting it is deferred to the validation block below -- see that
	// block for why, and for the guarantee that no return path between here
	// and there can hand back an unvalidated size.
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

	// Identity-first validation: both checks below are policy judgments about
	// already-decoded values, not failures to decode, and neither needs to
	// fire before fh.Name exists. Placed here, immediately before
	// parseExtraRecords, every return from this point on carries fh alongside
	// its error so the caller (Reader.dispatch) can refuse the member by name
	// instead of dropping it from the listing with no trace -- the same
	// contract parseExtraRecords already relies on below.
	//
	// No return path between the flags/size decode above and here can hand
	// back a header with an unvalidated size: every intermediate field
	// (mtime, CRC32, comp flags, host OS, name) fails with a bare
	// (nil, err) on a short or malformed payload, never exposing fh. So a
	// negative UnpackedSize is always rejected before ever escaping this
	// function, satisfying "sizes are validated where they are decoded" even
	// though the reject site has moved.
	//
	// The header's own untrustworthy value -- a meaningless UnpSizeUnknown
	// placeholder, or a negative size -- is deliberately left exactly as
	// decoded on fh, not clamped or zeroed. terminalEntry's cause is itself
	// the statement that nothing in the header is to be trusted; clamping
	// would destroy that evidence. See terminalEntry's doc comment and
	// ErrRarBombDetected's existing precedent for the same choice.
	if unpSizeUnknown {
		return fh, ErrUnpSizeUnknown
	}
	if fh.UnpackedSize < 0 {
		return fh, ErrCorruptFileHeader
	}

	// Parse optional extra records. Unlike every earlier failure in this
	// function, fh is returned alongside the error here: the name and every
	// size/CRC field are already decoded, so the caller can refuse the
	// member by name instead of dropping it silently.
	if err := parseExtraRecords(fh, h.Extra); err != nil {
		return fh, err
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
