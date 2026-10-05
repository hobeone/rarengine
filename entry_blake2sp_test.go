package rarengine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hashRecord is a file-hash extra record (type 2): hash type 0 (BLAKE2sp)
// followed by the 32-byte digest.
func hashRecord(digest []byte) extraRecordSpec {
	return extraRecordSpec{
		Type: extraRecordHash,
		Body: append(encodeVint(0), digest...),
	}
}

func digestOf(content string) []byte {
	d := blake2spSum([]byte(content))
	return d[:]
}

// flipped returns a copy of b with its first byte inverted.
func flipped(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 0xFF
	return out
}

func readMember(t *testing.T, archive []byte) (content string, readErr, closeErr error) {
	t.Helper()
	r := readerFor(archive)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	b, readErr := io.ReadAll(e)
	return string(b), readErr, e.Close()
}

// Real archives, read end to end against a hash of what was delivered.
//
// The expected SHA-256 values were computed from the source files
// generate.sh builds these from, so the content is compared against something
// that never passed through this library -- a clean verdict alone would also
// be produced by a member that was hashed over the wrong bytes AND recorded
// the matching wrong digest, which cannot happen with a real archive but is
// the shape of the mistake this guards.
func TestBlake2spFixturesVerify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		volumes []string
		size    int
		sha256  string
	}{
		// Over 1 MiB: 18,750 blocks dealt across all eight lanes, with a
		// partial final block.
		{"large compressed", []string{"rar5_blake2_large.rar"}, 1200037,
			"ac1524ad726f16cb3d77385a6d3e2be4472d202ab9a5f0e7943313a4dd860219"},
		{"multi-volume stored", []string{
			"rar5_blake2_store_multi.part1.rar", "rar5_blake2_store_multi.part2.rar",
			"rar5_blake2_store_multi.part3.rar", "rar5_blake2_store_multi.part4.rar",
		}, 6001, "c610d37275985b2b8cee49df57afd54bdca09b1f96f82613bc7d346e3c5ff439"},
		{"multi-volume compressed", []string{
			"rar5_blake2_comp_multi.part01.rar", "rar5_blake2_comp_multi.part02.rar",
			"rar5_blake2_comp_multi.part03.rar", "rar5_blake2_comp_multi.part04.rar",
		}, 23907, "47bd450c1c94d99a0daeb9e936a77db737afb3ca52de4a2fd3a6e74fd60c2d3f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := make([]string, len(tc.volumes))
			for i, v := range tc.volumes {
				paths[i] = filepath.Join("testdata", v)
			}
			r := NewReader(fileVolumesOf(t, paths...))
			e, err := r.NextEntry()
			if err != nil {
				t.Fatalf("NextEntry: %v", err)
			}
			if e.Header.HasCRC32 || !e.Header.HasBlake2sp {
				t.Fatalf("fixture has HasCRC32=%v HasBlake2sp=%v; it no longer "+
					"exercises BLAKE2sp-only verification", e.Header.HasCRC32, e.Header.HasBlake2sp)
			}
			b, err := io.ReadAll(e)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if err := e.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if len(b) != tc.size {
				t.Fatalf("delivered %d bytes, want %d", len(b), tc.size)
			}
			sum := sha256.Sum256(b)
			if got := hex.EncodeToString(sum[:]); got != tc.sha256 {
				t.Fatalf("content sha256 = %s, want %s", got, tc.sha256)
			}
		})
	}
}

// One byte of a stored member's content wrong, with the header untouched: the
// recorded BLAKE2sp digest no longer matches and the verdict says so, naming
// BLAKE2sp rather than a CRC32 the header never recorded.
//
// Payload corruption does not disturb a block header's own CRC, so this
// reaches verifyChecksum rather than the header check.
func TestBlake2spStoredContentCorruptionIsAMismatch(t *testing.T) {
	var vols []string
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("rar5_blake2_store_multi.part%d.rar", i)
		if i == 2 {
			name = corruptedCopy(t, filepath.Join("testdata", name), 1000)
		} else {
			name = filepath.Join("testdata", name)
		}
		vols = append(vols, name)
	}
	r := NewReader(fileVolumesOf(t, vols...))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	_, readErr := io.ReadAll(e)
	closeErr := e.Close()
	for what, err := range map[string]error{"Read": readErr, "Close": closeErr} {
		if !errors.Is(err, ErrCRCMismatch) {
			t.Fatalf("%s = %v, want ErrCRCMismatch", what, err)
		}
		if !strings.Contains(err.Error(), "BLAKE2sp") || strings.Contains(err.Error(), "CRC32") {
			t.Fatalf("%s = %q, want a message naming BLAKE2sp and not CRC32", what, err)
		}
	}
}

// What distinguishes the two archive kinds is in the FIRST part's header, and
// that is what lets hashing be decided at admission. Measured with rar 7.12
// and pinned here so a regenerated fixture, or a rar that changed its mind,
// is caught: under -htb every part records a BLAKE2 record and no CRC32; under
// the default every part records a CRC32 and no BLAKE2 record.
func TestBlake2spMultiVolumeFirstHeaderDecides(t *testing.T) {
	partFlags := func(t *testing.T, path string) (fh *FileHeader) {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		v, err := openVolume(f)
		if err != nil {
			t.Fatal(err)
		}
		for {
			h, err := v.next()
			if err != nil {
				t.Fatalf("%s: no file header: %v", path, err)
			}
			if h.Type != headerTypeFile {
				continue
			}
			fh, err = parseFileHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			return fh
		}
	}
	for _, tc := range []struct {
		name  string
		parts []string
		blake bool
	}{
		{"-htb stored", []string{
			"rar5_blake2_store_multi.part1.rar", "rar5_blake2_store_multi.part2.rar",
			"rar5_blake2_store_multi.part3.rar", "rar5_blake2_store_multi.part4.rar",
		}, true},
		{"-htb compressed", []string{
			"rar5_blake2_comp_multi.part01.rar", "rar5_blake2_comp_multi.part02.rar",
			"rar5_blake2_comp_multi.part03.rar", "rar5_blake2_comp_multi.part04.rar",
		}, true},
		{"default CRC32", []string{
			"rar5_multi.part01.rar", "rar5_multi.part02.rar", "rar5_multi.part03.rar",
			"rar5_multi.part04.rar", "rar5_multi.part05.rar",
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, p := range tc.parts {
				fh := partFlags(t, filepath.Join("testdata", p))
				if fh.HasBlake2sp != tc.blake || fh.HasCRC32 == tc.blake {
					t.Errorf("%s: HasBlake2sp=%v HasCRC32=%v, want blake=%v and the other absent",
						p, fh.HasBlake2sp, fh.HasCRC32, tc.blake)
				}
				if wantFirst := i == 0; fh.FirstBlock != wantFirst {
					t.Errorf("%s: FirstBlock=%v", p, fh.FirstBlock)
				}
			}
		})
	}
}

// Hashing runs exactly when the first header records a BLAKE2 digest, so a
// member that records none carries no hasher and pays nothing.
func TestBlake2spHasherIsStartedOnlyWhenTheFirstHeaderRecordsOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		fh   FileHeader
		want bool
	}{
		{"crc32 only", FileHeader{HasCRC32: true}, false},
		{"no digest", FileHeader{}, false},
		{"blake2sp only", FileHeader{HasBlake2sp: true}, true},
		{"both", FileHeader{HasCRC32: true, HasBlake2sp: true}, true},
		// The digest of an encrypted -htb member is a MAC, compared never,
		// so hashing its plaintext would be pure cost.
		{"encrypted", FileHeader{HasBlake2sp: true, Encrypted: true}, false},
		{"mac", FileHeader{HasBlake2sp: true, UseMac: true}, false},
	} {
		fh := tc.fh
		_, got := newEntry(&fh, strings.NewReader(""), nil).src.(*hashedSource)
		if got != tc.want {
			t.Errorf("%s: hasher started = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The same member through the whole parse -> admit -> read path, with the
// digest(s) the header records stated explicitly. These are the cases the
// verdict rules exist for, so each wrong-digest case must be the ONLY thing
// wrong with its archive.
func TestBlake2spVerdictRules(t *testing.T) {
	const content = "the quick brown fox jumps over the lazy dog, repeatedly: " +
		"0123456789012345678901234567890123456789012345678901234567890123456789"
	good := digestOf(content)

	for _, tc := range []struct {
		name string
		spec memberSpec
		// wantErr nil means clean; wantMsg is checked when wantErr is not nil.
		wantErr error
		wantMsg []string
		notMsg  []string
	}{
		{
			name: "blake2sp only, correct",
			spec: memberSpec{extraRecords: []extraRecordSpec{hashRecord(good)}},
		},
		{
			name:    "blake2sp only, wrong digest",
			spec:    memberSpec{extraRecords: []extraRecordSpec{hashRecord(flipped(good))}},
			wantErr: ErrCRCMismatch,
			wantMsg: []string{"BLAKE2sp"},
			notMsg:  []string{"CRC32"},
		},
		{
			name: "both present, both correct",
			spec: memberSpec{withCRC: true, extraRecords: []extraRecordSpec{hashRecord(good)}},
		},
		{
			// If only the BLAKE2sp were compared, or only the CRC32, one of
			// the next two would complete clean.
			name: "both present, CRC32 wrong",
			spec: memberSpec{
				rawCRC:       new(crc32.ChecksumIEEE([]byte(content)) ^ 1),
				extraRecords: []extraRecordSpec{hashRecord(good)},
			},
			wantErr: ErrCRCMismatch,
			wantMsg: []string{"CRC32"},
		},
		{
			name:    "both present, BLAKE2sp wrong",
			spec:    memberSpec{withCRC: true, extraRecords: []extraRecordSpec{hashRecord(flipped(good))}},
			wantErr: ErrCRCMismatch,
			wantMsg: []string{"BLAKE2sp"},
		},
		{
			// The size == 0 gate sits above every digest arm: nothing was
			// produced, so a digest that matches nothing is not a mismatch.
			name: "empty member with a BLAKE2sp record",
			spec: memberSpec{
				extraRecords: []extraRecordSpec{hashRecord(good)},
				unpackedSz:   new(int64(0)), packedSz: new(int64(0)),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			spec.name = "f.bin"
			if spec.unpackedSz == nil {
				spec.content = content
			}
			spec.extraFileFlags = 0
			archive := rar5Archive(t, false, rar5Member(t, spec))
			got, readErr, closeErr := readMember(t, archive)
			if spec.unpackedSz == nil && got != content {
				t.Fatalf("content = %q", got)
			}
			if tc.wantErr == nil {
				if readErr != nil || closeErr != nil {
					t.Fatalf("Read = %v, Close = %v, want both nil", readErr, closeErr)
				}
				return
			}
			for what, err := range map[string]error{"Read": readErr, "Close": closeErr} {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("%s = %v, want %v", what, err, tc.wantErr)
				}
				for _, m := range tc.wantMsg {
					if !strings.Contains(err.Error(), m) {
						t.Fatalf("%s = %q, want it to contain %q", what, err, m)
					}
				}
				for _, m := range tc.notMsg {
					if strings.Contains(err.Error(), m) {
						t.Fatalf("%s = %q, must not contain %q", what, err, m)
					}
				}
			}
		})
	}
}

// UseMac keeps a BLAKE2sp record unverifiable: the recorded value is a
// key-derived MAC, which this library cannot compute, and a digest that
// happens to be correct must not be compared as though it were a plain hash.
// Built directly -- a UseMac header without an encryption record is not
// something rar writes, which is the point: the verdict follows the flag.
func TestBlake2spWithUseMacIsStillUnverifiable(t *testing.T) {
	const content = "mac-protected"
	e := entryOver(content, &FileHeader{
		Name: "m.bin", UnpackedSize: int64(len(content)), LastBlock: true,
		UseMac: true, HasBlake2sp: true, Blake2sp: digestOf(content),
	})
	assertUnverifiable(t, e, content, "key-derived MAC over a BLAKE2sp digest")
}

// A BLAKE2sp digest recorded by the header in force that nothing computed is
// refused, not passed. No archive rar writes reaches it (the first part
// always records one too), but "the header disagrees with itself" must not be
// a way to choose "nothing to check".
func TestBlake2spRecordedButNeverComputedIsUnverifiable(t *testing.T) {
	const content = "first half|second half"
	const half = len("first half|")
	first := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "x.bin", content: content[:half], notLast: true,
		unpackedSz: new(int64(len(content))), packedSz: new(int64(half)),
	}))
	second := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "x.bin", content: content[half:], notFirst: true,
		unpackedSz: new(int64(len(content))), packedSz: new(int64(len(content) - half)),
		extraRecords: []extraRecordSpec{hashRecord(digestOf(content))},
	}))
	r := NewReader(volumesOf(first, second))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	assertUnverifiable(t, e, content, "BLAKE2sp digest that was not computed")
}

// The digest that matters is the LAST part's. The first part's record covers
// that part's packed bytes (unrar: "Pack-BLAKE2"), so a member whose first
// record is garbage but whose final record is the whole-file hash must read
// clean -- and one whose final record is wrong must not, whatever the first
// part says. Together they pin that the comparison reads e.cur, not Header.
func TestBlake2spSplitMemberComparesTheLastPartsDigest(t *testing.T) {
	const content = "first half|second half"
	const half = len("first half|")
	build := func(final []byte) (v1, v2 []byte) {
		v1 = rar5Archive(t, false, rar5Member(t, memberSpec{
			name: "x.bin", content: content[:half], notLast: true,
			unpackedSz: new(int64(len(content))), packedSz: new(int64(half)),
			// Not the whole-file digest, and nothing like it.
			extraRecords: []extraRecordSpec{hashRecord(digestOf("packed bytes of part one"))},
		}))
		v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
			name: "x.bin", content: content[half:], notFirst: true,
			unpackedSz: new(int64(len(content))), packedSz: new(int64(len(content) - half)),
			extraRecords: []extraRecordSpec{hashRecord(final)},
		}))
		return v1, v2
	}

	t.Run("correct final digest", func(t *testing.T) {
		v1, v2 := build(digestOf(content))
		e, err := NewReader(volumesOf(v1, v2)).NextEntry()
		if err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(e); err != nil || string(b) != content {
			t.Fatalf("ReadAll = %q, %v", b, err)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
	})
	t.Run("wrong final digest", func(t *testing.T) {
		v1, v2 := build(flipped(digestOf(content)))
		e, err := NewReader(volumesOf(v1, v2)).NextEntry()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, e)
		if err := e.Close(); !errors.Is(err, ErrCRCMismatch) {
			t.Fatalf("Close = %v, want ErrCRCMismatch", err)
		}
	})
}

// Hashing a member's bytes allocates nothing per Read. The one allocation a
// BLAKE2sp member costs is its hasher, made once at admission, which is why
// this measures reads on an entry that already exists. 100 reads of 4 KiB stay
// well inside the 1.2 MB member, so none of them is the finishing read that
// computes the digest.
func TestBlake2spReadDoesNotAllocate(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_blake2_large.rar")))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if _, ok := e.src.(*hashedSource); !ok {
		t.Fatalf("fixture member is not being hashed: src is %T", e.src)
	}
	buf := make([]byte, 4096)
	// Warm up: the first reads fill the decoder's window and tables.
	for range 4 {
		if _, err := e.Read(buf); err != nil {
			t.Fatalf("warm-up Read: %v", err)
		}
	}
	if n := testing.AllocsPerRun(100, func() {
		if _, err := e.Read(buf); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}); n != 0 {
		t.Fatalf("Entry.Read of a BLAKE2sp member allocates %v times per call, want 0", n)
	}
}
