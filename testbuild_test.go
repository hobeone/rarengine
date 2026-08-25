package rarengine

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
)

// RAR5 archive construction for the test suite, in one place.
//
// Four files used to build these headers from raw bytes, and the pieces they
// shared were byte-for-byte identical: the signature, the size-vint-plus-CRC32
// block wrapper, the archive and end headers, and the file-header field order.
// A format-level correction had to be found and applied in each of them, which
// is why the count in issue #35 was wrong twice before this landed.
//
// One layout for each thing the format defines:
//
//   - rar5Block wraps a header payload. Everything below goes through it.
//   - buildRAR5Member writes the only file-header layout in the suite.
//     memberSpec is the descriptive way to reach it; rar5FileEntry and its
//     variants are the positional way, kept because thirty-odd call sites read
//     better with three arguments than with a struct literal.
//   - rar5BlockDeclaring builds a block of ANY type that declares payload
//     independent of any entry, which is what the payload-discard tests exist
//     to attack. It is not a member builder and does not become one.

// rar5Sig is the RAR5 signature, "Rar!\x1a\x07\x01\x00".
var rar5Sig = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}

// rar5Block frames a header payload: the size vint, then the payload, with a
// CRC32 over both prepended. Every header in this file is built with it.
func rar5Block(payload []byte) []byte {
	sizeV := encodeVint(uint64(len(payload)))
	var hashed bytes.Buffer
	hashed.Write(sizeV)
	hashed.Write(payload)
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, crc32.ChecksumIEEE(hashed.Bytes()))
	out.Write(hashed.Bytes())
	return out.Bytes()
}

// rar5ArchiveHeaderFlags returns the signature followed by an archive header
// carrying flags -- one volume's opening bytes.
func rar5ArchiveHeaderFlags(flags uint64) []byte {
	var p bytes.Buffer
	p.Write(encodeVint(headerTypeArchive))
	p.Write(encodeVint(0))
	p.Write(encodeVint(flags))

	var out bytes.Buffer
	out.Write(rar5Sig)
	out.Write(rar5Block(p.Bytes()))
	return out.Bytes()
}

// rar5ArchiveHeader is rar5ArchiveHeaderFlags for a multi-volume set, the
// default most fixtures want.
func rar5ArchiveHeader() []byte { return rar5ArchiveHeaderFlags(arcFlagMultiVol) }

// rar5EndHeader terminates a volume. No signature: it is never the first
// thing in one.
func rar5EndHeader() []byte {
	var p bytes.Buffer
	p.Write(encodeVint(headerTypeEnd))
	p.Write(encodeVint(0))
	return rar5Block(p.Bytes())
}

// rar5BlockDeclaring builds a RAR5 block of the given type declaring dataSize
// bytes of payload, with extra appended to the header's own fields.
//
// Deliberately not a member builder: it declares payload with no entry behind
// it, which is the shape the payload-discard tests (#48) attack and which no
// builder derived from a file can express.
func rar5BlockDeclaring(blockType uint64, dataSize int, extra []byte, withSig bool) []byte {
	var p bytes.Buffer
	p.Write(encodeVint(blockType))
	p.Write(encodeVint(headerFlagHasData))
	p.Write(encodeVint(uint64(dataSize)))
	p.Write(extra)

	var out bytes.Buffer
	if withSig {
		out.Write(rar5Sig)
	}
	out.Write(rar5Block(p.Bytes()))
	return out.Bytes()
}

// memberSpec describes one stored (method 0) RAR5 member. The zero value is an
// ordinary single-block member: notFirst and notLast are negative so that the
// common case needs no fields set.
type memberSpec struct {
	name    string
	content string

	// unpackedSz and packedSz default to len(content). Set them to make the
	// header lie about the size, which is how the bomb and truncation
	// fixtures are built. They are independent of each other and of the
	// payload actually written, so a block whose declared payload outlives
	// its declared content -- the fabricated-header attack -- is expressible
	// here.
	unpackedSz int64
	packedSz   int64

	solid   bool
	isDir   bool
	withCRC bool

	// unpackVersion sets the compression-algorithm version field. Zero is
	// RAR 5.0, the only version this library decodes; a nonzero value builds
	// the RAR7-shaped member Reader.dispatch must refuse.
	unpackVersion uint64

	// crcOf overrides what withCRC checksums, defaulting to content. A
	// multi-volume member's last part carries the WHOLE file's CRC32, not
	// just that part's own bytes, so a split fixture must set this to the
	// full reassembled content rather than the tail it actually carries.
	crcOf string

	// rawCRC, when non-nil, is written to the CRC32 field verbatim and
	// implies withCRC. withCRC/crcOf compute a checksum of real bytes; a
	// fixture that needs a value belonging to nothing -- a deliberate
	// mismatch -- states it here instead of hunting for content that hashes
	// to it.
	rawCRC *uint32

	// hostOS defaults to 0. FileHeader.Mode reads it (1 means Unix), so a
	// fixture asserting on file modes has to say which.
	hostOS uint64

	notFirst bool // clears FirstBlock: this is a continuation block
	notLast  bool // clears LastBlock: the member continues in the next volume

	// extraFileFlags, extraCompFlags and extraBlockFlags are OR'd into the
	// three flag words after everything above has had its say. They exist so
	// a fixture can set a bit this struct does not name -- notably
	// fileFlagUnpSizeUnknown -- without a second copy of the header layout,
	// which is how this suite came to have four of them.
	extraFileFlags  uint64
	extraCompFlags  uint64
	extraBlockFlags uint64

	// badName declares a longer name than the header carries, so
	// parseFileHeader fails its bounds check while the BLOCK header stays
	// CRC-valid. That is the case the traversal must skip rather than stop on.
	badName bool

	// badEncVersion attaches a file-encryption extra record declaring an
	// unsupported version. It fails LATER than badName does -- inside
	// parseExtraRecords, after the name has been decoded -- which is the
	// only failure that yields a header alongside its error, so the member
	// can be refused by name instead of vanishing from the listing.
	badEncVersion bool

	// encRecord attaches a raw file-encryption extra record body (everything
	// after the record-type vint). Unlike badEncVersion, which builds one
	// specific malformed record, this lets a test state the encryption
	// metadata it needs -- notably an encrypted member with no check value,
	// which rar never produces but the format permits.
	encRecord []byte
}

// rar5Member builds one RAR5 file block followed by its payload.
func rar5Member(t testing.TB, s memberSpec) []byte {
	t.Helper()
	return buildRAR5Member(s)
}

// buildRAR5Member is rar5Member without a testing.TB, so the positional
// builders below can share this layout rather than restating it. Nothing here
// can fail, which is why rar5Member's t only ever marked it a helper.
func buildRAR5Member(s memberSpec) []byte {
	content := []byte(s.content)

	unpacked := s.unpackedSz
	if unpacked == 0 {
		unpacked = int64(len(content))
	}
	packed := s.packedSz
	if packed == 0 {
		packed = int64(len(content))
	}

	hasCRC := s.withCRC || s.rawCRC != nil

	var fileFlags uint64
	if s.isDir {
		fileFlags |= fileFlagIsDir
	}
	if hasCRC {
		fileFlags |= fileFlagHasCRC32
	}
	fileFlags |= s.extraFileFlags

	var f bytes.Buffer
	f.Write(encodeVint(fileFlags))
	f.Write(encodeVint(uint64(unpacked)))
	f.Write(encodeVint(0)) // attributes
	if hasCRC {
		var crcBuf [4]byte
		if s.rawCRC != nil {
			binary.LittleEndian.PutUint32(crcBuf[:], *s.rawCRC)
		} else {
			crcContent := content
			if s.crcOf != "" {
				crcContent = []byte(s.crcOf)
			}
			binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(crcContent))
		}
		f.Write(crcBuf[:])
	}
	// Compression flags: method lives in bits 7..9, so zero is store (method
	// 0). fileCompSolid is bit 6, and the unpack version is bits 0..5.
	var compFlags uint64
	if s.solid {
		compFlags |= fileCompSolid
	}
	// Masked with a literal, not fileCompVersion: a test that builds its
	// input with the same constant the parser reads it with moves whenever
	// that constant is wrong, and agrees with it either way.
	compFlags |= s.unpackVersion & 0x3f
	compFlags |= s.extraCompFlags
	f.Write(encodeVint(compFlags))
	f.Write(encodeVint(s.hostOS))

	name := []byte(s.name)
	if s.badName {
		f.Write(encodeVint(uint64(len(name) + 16)))
	} else {
		f.Write(encodeVint(uint64(len(name))))
	}
	f.Write(name)

	blockFlags := uint64(headerFlagHasData)
	if s.notFirst {
		blockFlags |= headerFlagDataNotFirst
	}
	if s.notLast {
		blockFlags |= headerFlagDataNotLast
	}
	blockFlags |= s.extraBlockFlags

	// The extra area sits at the END of the header payload, and its length is
	// declared before the data size -- so it has to be built before the block
	// header fields are written.
	var extra bytes.Buffer
	if s.badEncVersion {
		var rec bytes.Buffer
		rec.Write(encodeVint(1))  // record type: encryption
		rec.Write(encodeVint(99)) // version: not 0, so unsupported
		extra.Write(encodeVint(uint64(rec.Len())))
		extra.Write(rec.Bytes())
		blockFlags |= headerFlagHasExtra
	}
	if s.encRecord != nil {
		var rec bytes.Buffer
		rec.Write(encodeVint(1)) // record type: encryption
		rec.Write(s.encRecord)
		extra.Write(encodeVint(uint64(rec.Len())))
		extra.Write(rec.Bytes())
		blockFlags |= headerFlagHasExtra
	}

	var p bytes.Buffer
	p.Write(encodeVint(headerTypeFile))
	p.Write(encodeVint(blockFlags))
	if extra.Len() > 0 {
		p.Write(encodeVint(uint64(extra.Len())))
	}
	p.Write(encodeVint(uint64(packed)))
	p.Write(f.Bytes())
	p.Write(extra.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(p.Bytes()))
	out.Write(content)
	return out.Bytes()
}

// rar5Archive concatenates the RAR5 signature, an archive header, and each
// member, producing one volume's bytes.
func rar5Archive(t testing.TB, solid bool, members ...[]byte) []byte {
	t.Helper()
	var flags uint64
	if solid {
		flags |= arcFlagSolid
	}
	out := rar5ArchiveHeaderFlags(flags)
	for _, m := range members {
		out = append(out, m...)
	}
	return out
}

// rar5FileEntry emits a store-method file block plus its payload. The block's
// declared DataSize comes from len(payload) while unpackedSize is stated
// separately, so passing a payload longer than unpackedSize produces an entry
// whose packed block has bytes left over once the declared content has been
// produced.
func rar5FileEntry(name string, unpackedSize uint64, declaredCRC uint32, payload []byte) []byte {
	return rar5EntryComp(name, 0, unpackedSize, declaredCRC, payload)
}

// rar5EntryComp is rar5FileEntry with the compression-info vint exposed, so a
// test can set fileCompSolid (0x40) or a method without rebuilding the block.
// Method lives in bits 7-9 of the same vint, so 0 is store either way.
func rar5EntryComp(name string, compFlags uint64, unpackedSize uint64, declaredCRC uint32, payload []byte) []byte {
	return rar5EntryFlags(name, compFlags, headerFlagHasData, unpackedSize, declaredCRC, payload)
}

// rar5EntryFlags is rar5EntryComp with the BLOCK header flags exposed as well,
// so a test can mark an entry as continuing into the next volume
// (headerFlagDataNotLast) without restating the header layout.
//
// The three of these are a positional face over buildRAR5Member, not a second
// builder: name, size and CRC are what their call sites vary, and a struct
// literal at each of them would read worse. hostOS is 1 (Unix), which is what
// this family has always written.
func rar5EntryFlags(name string, compFlags uint64, blockFlags uint64, unpackedSize uint64, declaredCRC uint32, payload []byte) []byte {
	return buildRAR5Member(memberSpec{
		name:            name,
		content:         string(payload),
		unpackedSz:      int64(unpackedSize),
		rawCRC:          &declaredCRC,
		hostOS:          1,
		extraCompFlags:  compFlags,
		extraBlockFlags: blockFlags,
	})
}

// volumesOf returns a closed channel carrying each part as a volume.
func volumesOf(parts ...[]byte) <-chan io.ReadCloser {
	ch := make(chan io.ReadCloser, len(parts))
	for _, p := range parts {
		ch <- &mockReadCloser{bytes.NewReader(p)}
	}
	close(ch)
	return ch
}
