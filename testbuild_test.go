package rarengine

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// rar5Block frames a header payload: the size vint, then the payload, with a
// CRC32 over both prepended. Every header in this file is built with it.
func rar5Block(payload []byte) []byte {
	sizeV := encodeVint(uint64(len(payload)))
	var hashed bytes.Buffer
	hashed.Write(sizeV)
	hashed.Write(payload)
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(hashed.Bytes()))
	var out bytes.Buffer
	out.Write(crcBuf[:])
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
	out.Write(rar5Signature)
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
		out.Write(rar5Signature)
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

	// unpackedSz and packedSz default to len(content) when nil. Set them to
	// make the header lie about the size, which is how the bomb and
	// truncation fixtures are built. They are independent of each other and
	// of the payload actually written, so a block whose declared payload
	// outlives its declared content -- the fabricated-header attack -- is
	// expressible here.
	//
	// Pointers rather than a zero-means-absent int64, because ZERO IS A
	// VALUE these fixtures need: a member declaring UnpackedSize 0 while
	// carrying a payload is precisely the shape whose leftover bytes get
	// parsed as the next block header. Read as "absent", that declaration
	// was silently rewritten to len(content) and the attack stopped being
	// expressible -- by the one builder that had always been able to state
	// it. Write new(int64(n)); nil asks for the default.
	unpackedSz *int64
	packedSz   *int64

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

	// encRecord attaches a raw file-encryption extra record body (everything
	// after the record-type vint), letting a test state the encryption
	// metadata it needs: an encrypted member with no check value, which rar
	// never produces but the format permits, or -- as encodeVint(99) -- a
	// record declaring an unsupported version. That second one fails LATER
	// than badName does, inside parseExtraRecords and after the name has been
	// decoded, which is the only failure yielding a header alongside its
	// error, so the member can be refused by name instead of vanishing from
	// the listing. A dedicated badEncVersion flag built exactly that record
	// and nothing else, so it was this field with one value hard-coded.
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

	unpacked := int64(len(content))
	if s.unpackedSz != nil {
		unpacked = *s.unpackedSz
	}
	packed := int64(len(content))
	if s.packedSz != nil {
		packed = *s.packedSz
	}

	// crcOf counts: it states WHAT to checksum, so reading it as "no checksum
	// unless withCRC is also set" made a stated field a silent no-op.
	hasCRC := s.withCRC || s.rawCRC != nil || s.crcOf != ""

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
	//
	// A version the field cannot hold is refused rather than masked. The
	// field is six bits, so 64 came out as 0 -- unpackVersionRAR5 -- and a
	// fixture built to be refused for its version was emitted as an ordinary
	// RAR5 member that decoded cleanly. Same rule as the sizes above: a
	// builder does not quietly rewrite what its caller declared.
	if s.unpackVersion > 0x3f {
		panic(fmt.Sprintf("memberSpec.unpackVersion %d does not fit the "+
			"6-bit field; the format cannot express it", s.unpackVersion))
	}
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
	// Gated on the flag, not on extra.Len(): the parser reads this vint
	// whenever headerFlagHasExtra is set (header.go), so a fixture setting
	// that bit through extraBlockFlags with no records to go with it -- a
	// header claiming an extra area it does not carry, which is a thing an
	// attacker writes -- had the vint omitted, and every field after it read
	// one position early. The declared payload size became the extra size and
	// the header parsed as something nobody wrote.
	if blockFlags&headerFlagHasExtra != 0 {
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
		unpackedSz:      new(int64(unpackedSize)),
		packedSz:        new(int64(len(payload))),
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

// parseBuiltMember reads one built member back through the real parser.
//
// The builders' own tests assert on what a header SAYS once something reads
// it, rather than on the bytes -- a byte comparison against a hand-written
// expectation is a second copy of the layout, which is the thing this file
// exists to have one of.
func parseBuiltMember(t *testing.T, block []byte) *FileHeader {
	t.Helper()
	v, err := openVolume(&mockReadCloser{
		bytes.NewReader(append(append([]byte{}, rar5Signature...), block...)),
	})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	h, err := v.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	fh, err := parseFileHeader(h)
	if err != nil {
		t.Fatalf("parseFileHeader: %v", err)
	}
	return fh
}

// A declared size of zero must reach the header, from both faces.
//
// Zero used to mean "absent, use len(content)", so a member declaring
// UnpackedSize 0 while carrying a payload -- the shape whose leftover packed
// bytes are what gets parsed as the next block header -- was silently rewritten
// into a member declaring its own length, and the packed-remainder fixtures
// stopped being expressible by the builder that had always been able to state
// them. No fixture passed zero at the time, so nothing failed; the capability
// had simply gone.
//
// Read back through the parser rather than compared as bytes, because what
// matters is what the header says once something reads it.
func TestBuilderPreservesADeclaredZeroSize(t *testing.T) {
	t.Run("positional", func(t *testing.T) {
		fh := parseBuiltMember(t, rar5FileEntry("zero.bin", 0, 0xabcd, []byte("carried anyway")))
		if fh.UnpackedSize != 0 {
			t.Fatalf("UnpackedSize = %d, want the declared 0", fh.UnpackedSize)
		}
		if fh.PackedSize != int64(len("carried anyway")) {
			t.Fatalf("PackedSize = %d, want %d", fh.PackedSize, len("carried anyway"))
		}
	})

	t.Run("memberSpec", func(t *testing.T) {
		fh := parseBuiltMember(t, rar5Member(t, memberSpec{
			name: "zero.bin", content: "carried anyway",
			unpackedSz: new(int64(0)), packedSz: new(int64(0)),
		}))
		if fh.UnpackedSize != 0 {
			t.Fatalf("UnpackedSize = %d, want the declared 0", fh.UnpackedSize)
		}
		if fh.PackedSize != 0 {
			t.Fatalf("PackedSize = %d, want the declared 0", fh.PackedSize)
		}
	})

	// And the default still derives from content when nothing is declared.
	t.Run("absent", func(t *testing.T) {
		fh := parseBuiltMember(t, rar5Member(t, memberSpec{name: "d.bin", content: "eight!!!"}))
		if fh.UnpackedSize != 8 || fh.PackedSize != 8 {
			t.Fatalf("sizes = %d/%d, want 8/8 derived from content",
				fh.UnpackedSize, fh.PackedSize)
		}
	})
}

// The builder must not silently rewrite what a fixture declared.
//
// Three ways it did. Each is the same defect wearing different clothes: a
// field the caller stated was read as a hint, and the archive that came out
// was not the archive the test asked for. None had a caller at the time --
// which is exactly why they had to be found by reading rather than by a
// failure.
func TestBuilderDoesNotRewriteWhatAFixtureDeclared(t *testing.T) {
	// A header may claim an extra area it does not carry: that is a thing an
	// attacker writes. The parser reads the extra-size vint from the FLAG, so
	// gating the vint on len(extra) omitted it, and every field after it was
	// read one position early -- the declared payload size arrived as the
	// extra size, and the header parsed as something nobody wrote.
	t.Run("an empty extra area still declares its size", func(t *testing.T) {
		fh := parseBuiltMember(t, rar5Member(t, memberSpec{
			name: "claims.bin", content: "eight!!!",
			extraBlockFlags: headerFlagHasExtra,
		}))
		if fh.Name != "claims.bin" {
			t.Fatalf("Name = %q, want claims.bin -- the fields shifted", fh.Name)
		}
		if fh.UnpackedSize != 8 || fh.PackedSize != 8 {
			t.Fatalf("sizes = %d/%d, want 8/8 -- the fields shifted",
				fh.UnpackedSize, fh.PackedSize)
		}
	})

	// crcOf says WHAT to checksum. Requiring withCRC alongside it made a
	// stated field a no-op: no flag, no CRC32, and a fixture built to carry a
	// deliberately wrong checksum carried none at all.
	t.Run("crcOf alone still writes a checksum", func(t *testing.T) {
		fh := parseBuiltMember(t, rar5Member(t, memberSpec{
			name: "wrong.bin", content: "real content", crcOf: "something else",
		}))
		if !fh.HasCRC32 {
			t.Fatal("HasCRC32 = false; crcOf was stated and ignored")
		}
		if want := crc32.ChecksumIEEE([]byte("something else")); fh.CRC32 != want {
			t.Fatalf("CRC32 = %#x, want %#x (the checksum of crcOf)", fh.CRC32, want)
		}
	})

	// The version field is six bits. Masking 64 produced 0 -- unpackVersionRAR5
	// -- so a fixture built to be refused for its version was emitted as an
	// ordinary member that decoded cleanly.
	t.Run("a version the field cannot hold is refused", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("unpackVersion 64 built a member instead of panicking")
			}
		}()
		_ = buildRAR5Member(memberSpec{name: "v.bin", content: "x", unpackVersion: 64})
	})
}
