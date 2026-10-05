package rarengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
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
	// unpacked size is not known (fileFlagUnpSizeUnknown). Decoding relies on
	// the declared size to tell a completed file from a truncated one, so a
	// file that declines to state it is refused rather than decoded on a size
	// that means nothing.
	ErrUnpSizeUnknown = errors.New("rarengine: file header declares an unknown unpacked size")
)

const (
	maxHeaderSize = 2097151 // 2MB - 1 byte, max valid 3-byte vint

	// Header types
	headerTypeArchive    = 1
	headerTypeFile       = 2
	headerTypeService    = 3
	headerTypeEncryption = 4
	headerTypeEnd        = 5

	// General Header Flags
	headerFlagHasExtra     = 0x0001
	headerFlagHasData      = 0x0002
	headerFlagDataNotFirst = 0x0008
	headerFlagDataNotLast  = 0x0010

	// Main Archive Header Flags
	arcFlagMultiVol = 0x0001
	arcFlagVolNum   = 0x0002
	arcFlagSolid    = 0x0004

	// File Header Flags
	fileFlagIsDir          = 0x0001
	fileFlagHasUnixMtime   = 0x0002
	fileFlagHasCRC32       = 0x0004
	fileFlagUnpSizeUnknown = 0x0008

	// File Compression Flags
	// fileCompVersion masks the unpack-version field of a file header's
	// compression-information vint. Zero is RAR 5.0; RAR 7.0 raised it, and
	// the two formats are otherwise indistinguishable from outside a file
	// header -- same signature, same block framing, same vint encoding.
	fileCompVersion = 0x0000003f

	fileCompSolid = 0x00000040

	// fileCompDictShift and fileCompDictMask locate the dictionary-size
	// exponent in the compression-information vint of an unpack-version-0
	// header: bits 10..13, a 4-bit exponent e meaning 128 KiB << e, so the
	// largest size the format can express is 128 KiB << 15 = 4 GiB. Bit 14 is
	// not part of the field in version 0 (RAR 7.0 widened it, which is the
	// version bump). dictBaseSize is the e = 0 size.
	fileCompDictShift = 10
	fileCompDictMask  = 0x0f
	dictBaseSize      = 128 << 10

	// File Encryption Extra Flags
	fileEncCheckPresent = 0x0001
	fileEncUseMac       = 0x0002

	// File header extra record types
	extraRecordEncryption = 0x01 // Encryption
	extraRecordHash       = 0x02 // File hash (Blake2sp)
	extraRecordTime       = 0x03 // File times

	// extraRecordVersion is the file-version record. Nothing here reads it, and
	// it is named only so parseExtraRecords can say that it is deliberately
	// outside the once-per-type rule.
	extraRecordVersion = 0x04

	extraRecordRedirection = 0x05 // File-system redirection: a link
)

// LinkType says what kind of link a member is, from the file-system
// redirection record in its header. The zero value, LinkNone, is an ordinary
// member.
type LinkType uint8

const (
	LinkNone LinkType = 0 // not a link

	LinkUnixSymlink     LinkType = 1
	LinkWindowsSymlink  LinkType = 2
	LinkWindowsJunction LinkType = 3
	LinkHardLink        LinkType = 4
	LinkFileCopy        LinkType = 5
)

// blockHeader represents a generic RAR5 block header.
type blockHeader struct {
	Type     uint64
	Flags    uint64
	DataSize int64
	Payload  []byte
	Extra    []extraRecord
}

// extraRecord represents metadata parsed from header extra area.
type extraRecord struct {
	Type uint64
	Data []byte
}

// archiveHeader represents a parsed main archive header.
type archiveHeader struct {
	MultiVolume  bool
	Solid        bool
	VolumeNumber int
}

// FileHeader represents a parsed file header inside the archive.
type FileHeader struct {
	Name         string
	PackedSize   int64
	UnpackedSize int64

	// The one-byte fields sit together so they share a word. FileHeader is
	// allocated once per member, and growing it past an allocator size class
	// costs every member of every archive: adding the link fields scattered
	// among the word-sized ones moved it from the 240-byte class to 256.
	IsDir      bool
	Solid      bool
	FirstBlock bool // true if this is the first block/volume-part of the file
	LastBlock  bool // true if this is the last block/volume-part of the file

	// LinkType is LinkNone for an ordinary member. Anything else means this
	// member is a link: it carries no payload, Read returns io.EOF at once,
	// and UnpackedSize is NOT a content size -- a symlink declares the length
	// of its target string and a hard link the size of the file it points at.
	// Creating the link is the caller's job; this library writes nothing.
	LinkType LinkType

	Method int // compression method: 0 = store, 1..5 = compress

	// UnpackVersion is the compression algorithm version this member's header
	// declares: 0 is RAR 5.0, and it is the only value this library can
	// decode. RAR 7.0 raised it, and nothing outside a file header
	// distinguishes the two formats -- same signature, same block framing,
	// same vint encoding -- so this field is the only place the difference is
	// visible. Reader.dispatch refuses anything else; see unpackVersionRAR5.
	UnpackVersion int

	// DictSize is the dictionary size, in bytes, this member's header
	// DECLARES: 128 KiB << e for the 4-bit exponent e in the
	// compression-information vint. It is what the encoder was permitted to
	// use, not what the stream did use, so a member is never refused for it
	// -- a 60 MB file archived with -md64m declares 64 MB and can decode
	// inside a 32 MiB window, when its matches never reach that far. It is read
	// for one purpose: telling a stream that outran this library's window
	// apart from a corrupt one (see ErrDictionaryTooLarge). Zero when the
	// header's unpack version is not 0, where the field has a different
	// layout this library does not interpret.
	DictSize int64

	CRC32       uint32
	HasCRC32    bool
	HasBlake2sp bool
	Blake2sp    []byte // 32-byte BLAKE2sp hash
	// Encrypted reports that the member's content is encrypted, from RAR5's
	// encryption extra record. It reports that the member carries such a
	// record, not that the record is usable: it is set even when that
	// record fails to parse, in which case the parse error refuses the
	// member.
	Encrypted bool
	KdfCount  int
	// Salt is the PBKDF2 salt for an encrypted member.
	Salt             []byte
	IV               []byte
	UseMac           bool
	EncCheck         []byte
	ModificationTime time.Time
	HostOS           uint64
	Attributes       uint64

	// LinkTarget is the target the archive names, exactly as stored. It is
	// attacker-controlled and deliberately NOT sanitized the way Name is: a
	// legitimate target such as "../lib/x" is exactly what a consumer needs
	// to see, and rewriting it would destroy it. A consumer must validate it
	// before creating anything -- an absolute path or a ".." that escapes the
	// extraction root is a traversal -- and must do the same for Name. It is
	// never empty and never contains a NUL byte when LinkType is not
	// LinkNone. Empty for an ordinary member.
	LinkTarget string
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

// readBlockHeader reads and validates a RAR5 block header from the stream.
func readBlockHeader(r io.Reader) (*blockHeader, error) {
	var sizeBuf [7]byte
	_, err := io.ReadFull(r, sizeBuf[:])
	if err != nil {
		return nil, err
	}

	crc := binary.LittleEndian.Uint32(sizeBuf[0:4])

	// Decode the header size vint starting at sizeBuf[4:]
	sizeV, n, err := decodeVint(sizeBuf[4:])
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
// shared by both readBlockHeader's plaintext path and headerDecrypter's
// decrypted-header path so the two don't duplicate this parsing logic.
func parseBlockHeaderFields(buf []byte, n int) (*blockHeader, error) {
	payload := buf[n:]

	hType, nType, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nType:]

	flags, nFlags, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	h := &blockHeader{
		Type:  hType,
		Flags: flags,
	}

	var extraSize uint64
	if flags&headerFlagHasExtra > 0 {
		exSizeV, nEx, err := decodeVint(payload)
		if err != nil {
			return nil, err
		}
		extraSize = exSizeV
		payload = payload[nEx:]
	}

	if flags&headerFlagHasData > 0 {
		dtSizeV, nDt, err := decodeVint(payload)
		if err != nil {
			return nil, err
		}
		h.DataSize = int64(dtSizeV)
		if h.DataSize < 0 {
			return nil, ErrCorruptBlockHeader
		}
		payload = payload[nDt:]
	}

	// Compared as uint64 against uint64, never by casting the vint to int.
	// A vint carries 70 bits, so int(exSizeV) can wrap negative -- and a
	// negative extraSize passes "len(payload) < extraSize", then panics the
	// process at payload[:len(payload)-extraSize]. Keeping the declared
	// length in the type it was decoded in is what makes the bound a bound;
	// the cast below is safe only because this comparison already ran.
	if uint64(len(payload)) < extraSize {
		return nil, ErrCorruptBlockHeader
	}

	h.Payload = payload[:len(payload)-int(extraSize)]

	extraPayload := payload[len(payload)-int(extraSize):]
	for len(extraPayload) > 0 {
		exRecSizeV, nExRecSize, err := decodeVint(extraPayload)
		if err != nil {
			return nil, err
		}
		extraPayload = extraPayload[nExRecSize:]
		// Same bound in the same type, for the same reason as extraSize above.
		if uint64(len(extraPayload)) < exRecSizeV {
			return nil, ErrCorruptBlockHeader
		}
		exRecSize := int(exRecSizeV)

		recData := extraPayload[:exRecSize]
		extraPayload = extraPayload[exRecSize:]

		fType, nFType, err := decodeVint(recData)
		if err != nil {
			return nil, err
		}
		h.Extra = append(h.Extra, extraRecord{
			Type: fType,
			Data: recData[nFType:],
		})
	}

	return h, nil
}

// parseArchiveHeader decodes the main archive header details.
func parseArchiveHeader(h *blockHeader) (*archiveHeader, error) {
	if h.Type != headerTypeArchive {
		return nil, ErrBadBlockHeader
	}
	payload := h.Payload

	flags, nFlags, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	ah := &archiveHeader{
		MultiVolume:  flags&arcFlagMultiVol > 0,
		Solid:        flags&arcFlagSolid > 0,
		VolumeNumber: -1,
	}

	if flags&arcFlagVolNum > 0 {
		volNum, _, err := decodeVint(payload)
		if err != nil {
			return nil, err
		}
		// Bounded in the type it was decoded in, like every other declared
		// length here. A vint carries 70 bits, so int(volNum) can wrap
		// negative -- and negative is this field's encoding for "the archive
		// omitted it", which VolumeNumber reports as index 0. A crafted
		// archive could therefore claim to be the first volume of a set by
		// declaring an enormous volume number.
		if volNum > math.MaxInt {
			return nil, fmt.Errorf("%w: volume number %d does not fit in an int",
				ErrCorruptBlockHeader, volNum)
		}
		ah.VolumeNumber = int(volNum)
	}

	return ah, nil
}

// parseEncryptionRecord decodes RAR5 encryption extra record details.
func parseEncryptionRecord(fh *FileHeader, b []byte) error {
	// Presence, not validity. This is the only place Encrypted is set, so the
	// flag means the archive carries an encryption record for this member --
	// true whether or not the body below parses. Set after the checks, a
	// malformed record reported an encrypted member as plaintext. A body that
	// fails still returns its error, and that error is what refuses the member
	// and keeps buildChain from ever deriving a key from the zero salt and IV
	// such a header is left with.
	fh.Encrypted = true

	ver, nVer, err := decodeVint(b)
	if err != nil {
		return err
	}
	if ver != 0 {
		return ErrUnknownEncryptMethod
	}
	b = b[nVer:]

	encFlags, nEnc, err := decodeVint(b)
	if err != nil {
		return err
	}
	b = b[nEnc:]

	if len(b) < 33 {
		return ErrCorruptEncryptData
	}
	fh.KdfCount = int(b[0])
	fh.Salt = append([]byte(nil), b[1:17]...)
	fh.IV = append([]byte(nil), b[17:33]...)
	b = b[33:]

	if encFlags&fileEncCheckPresent > 0 {
		if len(b) < 12 {
			return ErrCorruptEncryptData
		}
		fh.EncCheck = append([]byte(nil), b[:12]...)
	}
	fh.UseMac = encFlags&fileEncUseMac > 0
	return nil
}

// parseHashRecord decodes RAR5 blake2sp file hash extra record details.
func parseHashRecord(fh *FileHeader, b []byte) error {
	hashType, nHash, err := decodeVint(b)
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
// alone: rar only sets fileFlagHasUnixMtime for whole-second times, and
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
	flags, n, err := decodeVint(data)
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

// parseRedirectionRecord decodes the file-system redirection extra record:
// a vint kind, a vint flags word (bit 0 says the target is a directory, which
// nothing here needs), a vint target length, and that many bytes of target.
//
// fh.LinkType and fh.LinkTarget are written only when the whole record is
// acceptable, so a header refused for its record never reports a link kind
// with no usable target.
//
// A kind outside 1..5 is refused as ErrUnsupportedFormat rather than skipped.
// Skipping would admit the member as an ordinary file, and an ordinary file
// with no payload is exactly the ErrTruncatedFile this record exists to
// explain; delivering an unknown kind as plain content is the other way to be
// wrong. Bytes after the declared target are tolerated: the length says where
// the target ends, and the record's own framing has already bounded the rest.
func parseRedirectionRecord(fh *FileHeader, b []byte) error {
	kind, n, err := decodeVint(b)
	if err != nil {
		return fmt.Errorf("%w: redirection record: %w", ErrCorruptFileHeader, err)
	}
	b = b[n:]
	if kind < uint64(LinkUnixSymlink) || kind > uint64(LinkFileCopy) {
		return fmt.Errorf("%w: file %q has a redirection record of unknown type %d",
			ErrUnsupportedFormat, fh.Name, kind)
	}

	_, n, err = decodeVint(b) // flags; bit 0 (target is a directory) is not exposed
	if err != nil {
		return fmt.Errorf("%w: redirection record: %w", ErrCorruptFileHeader, err)
	}
	b = b[n:]

	nameLen, n, err := decodeVint(b)
	if err != nil {
		return fmt.Errorf("%w: redirection record: %w", ErrCorruptFileHeader, err)
	}
	b = b[n:]
	// uint64 against uint64, like every declared length here: a vint carries
	// 70 bits, so int(nameLen) can wrap negative, pass this bound and panic at
	// the slice below.
	if uint64(len(b)) < nameLen {
		return fmt.Errorf("%w: redirection record declares a %d-byte target in %d bytes",
			ErrCorruptFileHeader, nameLen, len(b))
	}
	target := b[:nameLen]
	if len(target) == 0 {
		return fmt.Errorf("%w: redirection record names no target", ErrCorruptFileHeader)
	}
	if bytes.IndexByte(target, 0) >= 0 {
		return fmt.Errorf("%w: redirection target contains a NUL byte", ErrCorruptFileHeader)
	}

	fh.LinkType = LinkType(kind)
	fh.LinkTarget = string(target)
	return nil
}

// parseExtraRecords applies a file header's encryption, hash, time and
// redirection records to fh.
//
// A failing record does not stop the ones after it: every record is examined,
// and the first failure is returned once all of them have been.
// parseBlockHeaderFields has already cut each record to its own declared
// length and refused broken size or type framing, so one record's bad body
// cannot desynchronise the next. Stopping at the first failure let a malformed
// record placed ahead of the encryption record hide it entirely, and the
// header reported an encrypted member as plaintext.
//
// A record type this function parses may appear once. Two encryption
// records built one header out of both -- Salt, IV and UseMac from the
// second, EncCheck from the first -- with a nil error, which let a crafted
// archive clear UseMac and have a MAC compared as a CRC32, or pair one
// record's check value with the other's salt. Refused rather than resolved
// by choosing one: the header contradicts itself. The first record of a
// type is the one parsed, even when it fails; a later one is never read
// into the header.
func parseExtraRecords(fh *FileHeader, extra []extraRecord) error {
	var first error
	var seen [extraRecordRedirection + 1]bool // indexed by record type
	for _, e := range extra {
		// The version record (4) sits between the time and redirection
		// records and is not parsed, so it is excluded by name rather than by
		// the range: a repeat of it is not tracked either.
		if e.Type < extraRecordEncryption || e.Type > extraRecordRedirection ||
			e.Type == extraRecordVersion {
			continue // not a record this function parses; repeats are not tracked either
		}
		if seen[e.Type] {
			if first == nil {
				first = fmt.Errorf("%w: duplicate extra record of type %d", ErrCorruptFileHeader, e.Type)
			}
			continue
		}
		seen[e.Type] = true
		var err error
		switch e.Type {
		case extraRecordEncryption:
			err = parseEncryptionRecord(fh, e.Data)
		case extraRecordHash:
			err = parseHashRecord(fh, e.Data)
		case extraRecordTime:
			err = parseTimeRecord(fh, e.Data)
		case extraRecordRedirection:
			err = parseRedirectionRecord(fh, e.Data)
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

// parseFileHeader decodes the file header details from a block header.
//
// It is the ONLY function in this package permitted to return a non-nil
// *FileHeader alongside a non-nil error. Every failure up through the name
// field means there is no identity to report, so those paths return a nil
// header like any other parse failure. Three later failures return the
// header they built anyway, because by then the member's name and sizes are
// decoded and the caller (Reader.dispatch) can refuse the member BY NAME
// instead of dropping it from the listing with no trace:
//
//   - ErrUnpSizeUnknown, from the declared-size check
//   - ErrCorruptFileHeader, from a negative decoded UnpackedSize
//   - a failure inside parseExtraRecords, the lowest-priority of the three
//
// A fourth, a link whose header contradicts itself (it declares payload, or a
// further part), returns its header the same way and ranks after the extra
// records, since it can only be judged once they have said it is a link.
//
// All of these headers are equally complete: parseExtraRecords runs before
// either size check reports, so a header returned alongside ANY of these
// errors carries Name and Encrypted, and every other field is either decoded
// correctly or, for a field belonging to one of the records that failed,
// zero or partly filled from that record; UnpackedSize itself is decoded but
// not dependable once either size check has refused the header. The ERRORS
// still keep their old priority -- an unknown or negative size outranks a
// failing extra record -- so moving the parse earlier changed no caller's
// verdict, only what the header it's attached to contains.
//
// An exported wrapper used to stand in front of this and flatten all three to
// a nil header, which is why callers could not tell them apart from a header
// that never parsed. It had no callers outside tests once the traversal
// started using this form directly, and it is gone.
func parseFileHeader(h *blockHeader) (*FileHeader, error) {
	if h.Type != headerTypeFile && h.Type != headerTypeService {
		return nil, ErrBadBlockHeader
	}
	payload := h.Payload

	flags, nFlags, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nFlags:]

	// Captured here, at the point the flag is decoded, but not acted on until
	// the validation block below: the flag itself is decoded identity, not a
	// failure to decode, and the name has not been read yet.
	unpSizeUnknown := flags&fileFlagUnpSizeUnknown > 0

	fh := &FileHeader{
		IsDir:      flags&fileFlagIsDir > 0,
		FirstBlock: h.Flags&headerFlagDataNotFirst == 0,
		LastBlock:  h.Flags&headerFlagDataNotLast == 0,
		PackedSize: h.DataSize,
	}

	unpackedSize, nUnp, err := decodeVint(payload)
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

	attrs, nAttrs, err := decodeVint(payload) // Attributes
	if err != nil {
		return nil, err
	}
	fh.Attributes = attrs
	payload = payload[nAttrs:]

	if flags&fileFlagHasUnixMtime > 0 {
		if len(payload) < 4 {
			return nil, ErrCorruptFileHeader
		}
		mtime := binary.LittleEndian.Uint32(payload[0:4])
		fh.ModificationTime = time.Unix(int64(mtime), 0)
		payload = payload[4:]
	}

	if flags&fileFlagHasCRC32 > 0 {
		if len(payload) < 4 {
			return nil, ErrCorruptFileHeader
		}
		fh.CRC32 = binary.LittleEndian.Uint32(payload[0:4])
		fh.HasCRC32 = true
		payload = payload[4:]
	}

	compFlags, nComp, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	fh.UnpackVersion = int(compFlags & fileCompVersion)
	if fh.UnpackVersion == unpackVersionRAR5 {
		fh.DictSize = dictBaseSize << ((compFlags >> fileCompDictShift) & fileCompDictMask)
	}
	fh.Solid = compFlags&fileCompSolid > 0
	fh.Method = int((compFlags >> 7) & 7)
	payload = payload[nComp:]

	hostOS, nOS, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	fh.HostOS = hostOS
	payload = payload[nOS:]

	nameLen, nName, err := decodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[nName:]

	// uint64 against uint64: int(nameLen) wraps negative for a name length
	// with the sign bit set, which passes this check and then panics at
	// payload[:nameLen] -- a crafted header killing the host process.
	if uint64(len(payload)) < nameLen {
		return nil, ErrCorruptFileHeader
	}
	fh.Name = sanitizePath(string(payload[:nameLen]))

	// fh.Name is set before anything below can fail: no return path between
	// the flags/size decode above and here can hand back a header with an
	// unvalidated size, since every intermediate field (mtime, CRC32, comp
	// flags, host OS, name) fails with a bare (nil, err) on a short or
	// malformed payload, never exposing fh. So every header this function
	// returns alongside an error already has a name the caller
	// (Reader.dispatch) can refuse the member by, instead of dropping it
	// from the listing with no trace.
	//
	// The header's own untrustworthy value -- a meaningless UnpSizeUnknown
	// placeholder, or a negative size -- is deliberately left exactly as
	// decoded on fh, not clamped or zeroed. terminalEntry's cause is itself
	// the statement that nothing in the header is to be trusted; clamping
	// would destroy that evidence. See terminalEntry's doc comment and
	// ErrRarBombDetected's existing precedent for the same choice.
	//
	// Every extra record is attempted before either size check reports, so a
	// header refused for its size still carries what its archive encoded --
	// Encrypted above all, though UnpackedSize itself stays undependable once
	// a size check has refused the header. The ERRORS keep their priority:
	// ErrUnpSizeUnknown, then a negative decoded UnpackedSize, then a failing
	// extra record.
	extraErr := parseExtraRecords(fh, h.Extra)
	if unpSizeUnknown {
		return fh, ErrUnpSizeUnknown
	}
	if fh.UnpackedSize < 0 {
		return fh, ErrCorruptFileHeader
	}
	if extraErr != nil {
		return fh, extraErr
	}
	if fh.LinkType != LinkNone {
		// A link has no data. A header that names a target AND declares
		// payload bytes is both a link and a file, and delivering it as either
		// would hand the other half's bytes to the wrong consumer; one that
		// continues into a further part contradicts a member that has nothing
		// to continue, and one that claims to be a continuation contradicts a
		// member that has no earlier part: spliced into an ordinary member's
		// next volume, it would have ended that member as ErrTruncatedFile --
		// an accusation about the archive's content for what is a header
		// contradicting itself. Refused rather than reconciled, like every
		// other header that contradicts itself.
		if !fh.FirstBlock {
			return fh, fmt.Errorf("%w: link %q declares an earlier part",
				ErrCorruptFileHeader, fh.Name)
		}
		if fh.PackedSize != 0 {
			return fh, fmt.Errorf("%w: link %q declares %d bytes of payload",
				ErrCorruptFileHeader, fh.Name, fh.PackedSize)
		}
		if !fh.LastBlock {
			return fh, fmt.Errorf("%w: link %q declares a further part",
				ErrCorruptFileHeader, fh.Name)
		}
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
