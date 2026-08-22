# rarengine Traversal Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace rarengine's traversal layer with one where stream position and per-member verdict are owned by values rather than maintained by discipline, and delete the RAR3 decoding engine and `UnpackDir`.

**Architecture:** A `volume` type owns one RAR volume's bytes and the position within them; its `next()` skips the current block's remaining payload *before* reading the following header, so a header can never be parsed out of a previous block's payload. A `Reader` owns the volume chain and block dispatch; an `Entry` owns one member's reader chain, byte budget, running CRC32 and terminal verdict. `Window` owns the solid-history damage flag.

**Tech Stack:** Go (module `github.com/hobeone/rarengine`), stdlib only. `golangci-lint` v2 (`govet`, `staticcheck`, `errcheck`, `ineffassign`, `unused`). Differential oracle tests against the system `unrar` binary.

**Spec:** `docs/superpowers/specs/2026-08-21-rarengine-simplification-design.md`

## Global Constraints

- Quality gate before every commit, all five must pass:
  `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
- Commit messages follow Conventional Commits 1.0.0. Footer on every commit:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`
- Never push to `main`. Work happens on a branch; PRs are opened but never merged without explicit user approval.
- Zero-allocation applies to the 32 MB `Window` and `Reader.Reset` reuse **only**. Per-file objects are ordinary allocations. Do not reintroduce reused per-file reader structs.
- Never reintroduce a zeroing loop on the window history buffer.
- The window history bound in `Window.CopyBytes` (`distance > w.historyLen()`) must not be weakened.
- `ErrTruncatedFile` must never satisfy `errors.Is(err, io.EOF)`.
- AES key material (password, derived key bytes, salt) must never appear in error messages or log output.
- The library writes no files. Do not add filesystem access.

## PR boundary

- **PR 1 — subtractive (Tasks 1–3).** Deletes the RAR3 decoding engine and `UnpackDir`. Its review question is only "did any RAR5 behaviour change?", which is answerable because the RAR5 suite is untouched.
- **PR 2 — the rewrite (Tasks 4–14).** New traversal built alongside the old one, which stays green until Task 12 deletes it.

---

## File Structure

| File | Responsibility | Disposition |
|---|---|---|
| `volume.go` | One volume's bytes + position. Sole mover of the traversal stream. | Create (Task 4) |
| `reader.go` | Volume chain, block dispatch, member admission, password resolution. | Create (Task 8) |
| `entry.go` | One member: reader chain, byte budget, running CRC32, terminal verdict. | Create (Task 7) |
| `crypto.go` | `pbkdf2HmacSha256`, `verifyEncCheck`, `cbcDecryptReader`. Lifted verbatim. | Create (Task 6) |
| `window.go` | Adds `BeginFile` / `MarkIncomplete`; owns solid-history damage. | Modify (Task 5) |
| `header.go` | Unchanged parsing. `sanitizePath` stays. | Untouched |
| `header_rar3.go` | RAR3 header parsing for gonzbd's `InspectRar3`. Loses engine-only helpers. | Modify (Task 3) |
| `decoder30.go`, `engine_rar3.go` | RAR3 decoding. | Delete (Task 1) |
| `unpack.go` | `UnpackDir`. No consumer. | Delete (Task 2) |
| `decompressor.go`, `engine_rar5.go`, `filereader.go` | Old traversal. | Delete (Task 12) |

---

## Task 1: Delete the RAR3 decoding engine

**Files:**
- Delete: `decoder30.go`, `engine_rar3.go`, `decompressor_rar3_test.go`
- Modify: `decompressor.go` (version detection and engine selection)

**Interfaces:**
- Consumes: nothing.
- Produces: `ErrUnsupportedFormat = errors.New("rarengine: unsupported archive format")` in `decompressor.go`. Tasks 4 and 8 use it.

- [ ] **Step 1: Write the failing test**

Add to `decompressor_test.go`:

```go
func TestRAR3ArchiveIsRefusedAsUnsupported(t *testing.T) {
	// A bare RAR3 signature followed by a main header. Decoding RAR3 is no
	// longer supported; header parsing for it remains exported for callers
	// that inspect archives without decompressing them.
	sig := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}

	sd := NewStreamDecompressor(volumesOf(sig))
	_, err := sd.Next()
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("Next() error = %v, want ErrUnsupportedFormat", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestRAR3ArchiveIsRefusedAsUnsupported ./...`
Expected: FAIL with `undefined: ErrUnsupportedFormat`.

- [ ] **Step 3: Delete the RAR3 decoding files**

```bash
git rm decoder30.go engine_rar3.go decompressor_rar3_test.go
```

- [ ] **Step 4: Add the sentinel and make detection refuse RAR3**

In `decompressor.go`, add to the `var (...)` error block:

```go
	// ErrUnsupportedFormat reports an archive this library cannot decode.
	// RAR3 archives reach this: their headers remain parseable through
	// ReadRAR3BlockHeader and ParseRAR3FileHeader for callers that inspect
	// archives, but no RAR3 decoder is provided.
	ErrUnsupportedFormat = errors.New("rarengine: unsupported archive format")
```

Replace the engine-selection switch in `nextVolume` with:

```go
	sd.version = version
	if sd.engine == nil {
		if version != VersionRAR5 {
			_ = sd.currentVol.Close()
			sd.currentVol = nil
			return fmt.Errorf("%w: %v", ErrUnsupportedFormat, version)
		}
		sd.engine = newRAR5Engine(sd)
	}
```

- [ ] **Step 5: Run the full suite**

Run: `go test -race ./...`
Expected: PASS. Failures naming RAR3 decoding in retained test files mean those cases must be deleted — they test a decoder that no longer exists. Failures in RAR5 tests mean something was broken and must be fixed, not deleted.

- [ ] **Step 6: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass. `unused` may flag RAR3 helpers now orphaned; leave them for Task 3.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(rarengine): drop the RAR3 decoding engine

RAR3 decoding implemented only the store method, so any compressed RAR3
archive failed there anyway -- gonzbd's InspectRar3 documents routing around
it for exactly that reason. The engine carried a disproportionate share of the
security surface: lhdLarge, the unmeasurable-payload refusal, the fatal latch,
and the encryption re-check on two separate paths.

RAR3 header parsing is kept. It has a live consumer and none of the retired
constraints lived in it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Delete UnpackDir

**Files:**
- Delete: `unpack.go`, `unpack_test.go`, `unpack_damaged_test.go`, `unpack_refusal_test.go`, `unpack_realarchive_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. Removes `UnpackDir`, `UnpackOptions`, `UnpackResult`, `DamagedEntry`, `SortVolumes`, `ErrUnusableName`, `uniquePath`, `asDamaged`, `readVolumeIndex`, `getClassicVolumeIndex`, `setupSandbox`.

**Note:** `sanitizePath` lives in `header.go`, **not** in `unpack.go`. It is applied to every `fh.Name` at parse time and must survive this task. Verify with `grep -n sanitizePath header.go header_rar3.go` after deleting.

- [ ] **Step 1: Confirm there is no in-repo consumer**

Run: `grep -rn "UnpackDir\|UnpackOptions\|UnpackResult\|DamagedEntry\|SortVolumes" --include="*.go" . | grep -v "^./unpack"`
Expected: no output. Any output is a consumer that must be handled before deleting.

- [ ] **Step 2: Delete the files**

```bash
git rm unpack.go unpack_test.go unpack_damaged_test.go unpack_refusal_test.go unpack_realarchive_test.go
```

- [ ] **Step 3: Verify sanitizePath survived**

Run: `grep -n "sanitizePath" header.go header_rar3.go`
Expected: three hits — the definition in `header.go`, and one call in each of `header.go` and `header_rar3.go`. Zero hits means `sanitizePath` was deleted in error and must be restored.

- [ ] **Step 4: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass. `unused` may flag helpers that only `unpack.go` used; delete those it names.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(rarengine): delete UnpackDir, which has no consumer

gonzbd is the only consumer and uses none of it -- not UnpackOptions,
UnpackResult, DamagedEntry or SortVolumes. It reimplements extraction policy
itself, path sanitizer included, so this was a second copy of logic that
already exists elsewhere and only the other copy is exercised.

rarengine becomes a decode-and-inspect library that touches no filesystem.
sanitizePath is unaffected: it runs in the parsers on every fh.Name, not at a
write site.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Prune the orphaned RAR3 engine helpers

**Files:**
- Modify: `header_rar3.go`
- Modify: `discard_payload_test.go` (delete RAR3 cases)

**Interfaces:**
- Consumes: Tasks 1 and 2 complete.
- Produces: `header_rar3.go` containing only what `ReadRAR3BlockHeader` and `ParseRAR3FileHeader` need.

- [ ] **Step 1: Find what is now unused**

Run: `golangci-lint run ./... 2>&1 | grep unused`
Expected: names among `rar3ClaimsEncryption`, `rar3UsesFileLayout`, and block-type constants (`rar3BlockComment`, `rar3BlockAV`, `rar3BlockOldSub`, `rar3BlockProtect`, `rar3BlockSign`, `rar3BlockNewSub`, `rar3BlockTerminator`, `mhdPassword`, `mhdFirstVolume`).

- [ ] **Step 2: Delete the RAR3 cases from the crafted-archive tests**

In `discard_payload_test.go`, delete `rar3BlockDeclaring`, `fabricatedRAR3`, and every test function whose name ends `_RAR3`. They exercise the deleted engine's discard paths.

Do the same in `packed_drain_test.go` and `skip_damaged_test.go`: delete `_RAR3` test functions and any helper left with no caller.

- [ ] **Step 3: Delete the orphaned helpers from header_rar3.go**

Delete `rar3ClaimsEncryption` and `rar3UsesFileLayout`, and every constant `golangci-lint` named in Step 1. Keep `lhdSplitBefore`, `lhdSplitAfter`, `lhdPassword`, `lhdSolid`, `lhdLarge`, `lhdSalt`, `longBlock`, `rar3BlockMark`, `rar3BlockMain`, `rar3BlockFile` — verify each is still referenced by `ReadRAR3BlockHeader` or `ParseRAR3FileHeader` before keeping it:

Run: `grep -n "lhdSalt\|lhdLarge\|rar3BlockFile" header_rar3.go`

- [ ] **Step 4: Verify the RAR3 inspect surface still works**

Run: `go test -run "RAR3|Rar3" -race ./...`
Expected: PASS. `ReadRAR3BlockHeader` and `ParseRAR3FileHeader` must remain exported — gonzbd's `internal/rarheader` calls both.

Run: `go doc . ReadRAR3BlockHeader && go doc . ParseRAR3FileHeader`
Expected: both print documentation. An error means an exported symbol was lost.

- [ ] **Step 5: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass, no `unused` findings.

- [ ] **Step 6: Commit and open PR 1**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(rar3): prune the helpers the deleted engine owned

rar3ClaimsEncryption and rar3UsesFileLayout existed for the engine's admission
and discard paths. What remains is what the two exported parsers need, which
is the whole of RAR3 support this library now offers.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
git push -u origin HEAD
gh pr create --title "refactor(rarengine): drop RAR3 decoding and UnpackDir" --body "See docs/superpowers/specs/2026-08-21-rarengine-simplification-design.md. Subtractive only -- no RAR5 behaviour change is intended, and the RAR5 suite is untouched."
```

---

## Task 4: The `volume` type

This is the keystone. Everything the plan deletes later is deleted because this holds.

**Files:**
- Create: `volume.go`
- Test: `volume_test.go`

**Interfaces:**
- Consumes: `ErrUnsupportedFormat` (Task 1), `ReadBlockHeader`, `BlockHeader`, `headerDecrypter` (existing).
- Produces:
  - `type volume struct { rc io.ReadCloser; body io.LimitedReader; hd *headerDecrypter }`
  - `func openVolume(rc io.ReadCloser) (*volume, error)`
  - `func (v *volume) next() (*BlockHeader, error)`
  - `func (v *volume) payload() io.Reader`
  - `func (v *volume) useEncryptedHeaders(key []byte)`
  - `func (v *volume) Close() error`

- [ ] **Step 1: Write the failing test**

Create `volume_test.go`:

```go
package rarengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// A block that declares payload, followed by a real block. next() must reach
// the second block without the caller discarding anything: the whole point of
// the type is that skipping is not a caller obligation.
func TestVolumeNextSkipsUnclaimedPayload(t *testing.T) {
	// An archive header declaring 20 bytes of payload, with a complete,
	// CRC-valid file block planted inside that payload. A traversal that
	// fails to skip parses the planted block as the next header.
	planted := rar5Block(func() []byte {
		var p bytes.Buffer
		p.Write(EncodeVint(HeaderTypeFile))
		p.Write(EncodeVint(0))
		return p.Bytes()
	}())
	archive := rar5BlockDeclaring(HeaderTypeArchive, len(planted), nil, true)

	real := rar5Block(func() []byte {
		var p bytes.Buffer
		p.Write(EncodeVint(HeaderTypeEnd))
		p.Write(EncodeVint(0))
		return p.Bytes()
	}())

	stream := append(append(append([]byte{}, archive...), planted...), real...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}

	h, err := v.next()
	if err != nil {
		t.Fatalf("first next(): %v", err)
	}
	if h.Type != HeaderTypeArchive {
		t.Fatalf("first block type = %d, want HeaderTypeArchive", h.Type)
	}

	h, err = v.next()
	if err != nil {
		t.Fatalf("second next(): %v", err)
	}
	if h.Type != HeaderTypeEnd {
		t.Fatalf("second block type = %d, want HeaderTypeEnd (the planted "+
			"file block was parsed out of the first block's payload)", h.Type)
	}
}

// payload() must not reach past the block's declared size, so a decoder
// cannot consume the following header.
func TestVolumePayloadIsBoundedByDataSize(t *testing.T) {
	const declared = 4
	trailing := []byte("SHOULD-NOT-BE-READABLE")
	blk := rar5BlockDeclaring(HeaderTypeFile, declared, nil, true)
	stream := append(append([]byte{}, blk...), append([]byte("DATA"), trailing...)...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	if _, err := v.next(); err != nil {
		t.Fatalf("next(): %v", err)
	}

	got, err := io.ReadAll(v.payload())
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != "DATA" {
		t.Fatalf("payload = %q, want %q", got, "DATA")
	}
}

// A RAR3 signature is not decodable. openVolume must say so rather than
// misparsing RAR3 blocks under the RAR5 layout.
func TestOpenVolumeRefusesRAR3(t *testing.T) {
	sig := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}
	_, err := openVolume(&mockReadCloser{bytes.NewReader(sig)})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("openVolume error = %v, want ErrUnsupportedFormat", err)
	}
}

// A volume truncated inside a block's payload must report exhaustion, not
// silently continue. The skip stops at EOF and the header read then fails.
func TestVolumeTruncatedInsidePayloadReportsEOF(t *testing.T) {
	blk := rar5BlockDeclaring(HeaderTypeFile, 100, nil, true)
	stream := append(append([]byte{}, blk...), []byte("short")...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	if _, err := v.next(); err != nil {
		t.Fatalf("first next(): %v", err)
	}
	_, err = v.next()
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("second next() error = %v, want io.EOF or io.ErrUnexpectedEOF", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestVolume|TestOpenVolume" ./...`
Expected: FAIL with `undefined: openVolume`.

- [ ] **Step 3: Write the implementation**

Create `volume.go`:

```go
package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// volume owns one RAR volume's byte stream and the position within it.
//
// It is the only way the traversal obtains a block header, and next()
// re-establishes the block boundary itself before reading one. A header
// therefore cannot be parsed out of a previous block's payload -- not because
// every caller remembers to discard, but because no caller is offered the
// chance to skip.
//
// The skip is at the front of the only entrance deliberately. A finish()-style
// call after the fact would be exactly as forgettable as the per-case discard
// this type replaces; putting it before the read discharges the obligation as
// a side effect of asking for the thing the caller wanted anyway.
//
// The count lives here rather than beside the traversal because a volume
// advance CONSTRUCTS A NEW volume rather than repointing this one. A count
// outliving the volume it describes is therefore not a rule to follow but a
// lifetime that cannot occur, which is what makes the previous cursor's
// invalidate/abandoned/settled distinction unnecessary.
type volume struct {
	rc io.ReadCloser

	// body is what remains of the current block's declared payload. It is the
	// bound on payload() as well as the amount next() skips, and those are the
	// same number by construction: a RAR5 file header's PackedSize is set from
	// the block's DataSize (header.go), so no second count can disagree.
	body io.LimitedReader

	// hd decrypts subsequent block headers once an encryption header has
	// yielded a key. nil means headers are plaintext.
	hd *headerDecrypter
}

var rar5Signature = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}

// openVolume reads and validates the RAR5 signature, leaving v positioned on
// the first block boundary. A RAR3 signature is reported as
// ErrUnsupportedFormat: its headers stay parseable through
// ReadRAR3BlockHeader for callers that inspect archives, but there is no RAR3
// decoder to hand the volume to.
func openVolume(rc io.ReadCloser) (*volume, error) {
	var sig [8]byte
	if _, err := io.ReadFull(rc, sig[:7]); err != nil {
		return nil, err
	}
	if !bytes.Equal(sig[:6], rar5Signature[:6]) {
		return nil, fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
	}
	switch sig[6] {
	case 0x00:
		return nil, fmt.Errorf("%w: RAR3", ErrUnsupportedFormat)
	case 0x01:
		if _, err := io.ReadFull(rc, sig[7:]); err != nil {
			return nil, err
		}
		if sig[7] != 0x00 {
			return nil, fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
		}
	default:
		return nil, fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
	}
	return &volume{rc: rc}, nil
}

// next skips whatever remains of the current block's payload, then reads the
// following header. io.EOF means this volume is exhausted.
//
// A short skip is not an error here. When a volume is truncated the promised
// bytes are simply absent, io.Copy stops at the underlying EOF, and the header
// read below then fails -- which is the same signal as a volume that simply
// ended, and is handled in one place by the caller.
func (v *volume) next() (*BlockHeader, error) {
	if _, err := io.Copy(io.Discard, &v.body); err != nil {
		return nil, err
	}
	var (
		h   *BlockHeader
		err error
	)
	if v.hd != nil {
		h, err = v.hd.readEncryptedBlockHeader(v.rc)
	} else {
		h, err = ReadBlockHeader(v.rc)
	}
	if err != nil {
		return nil, err
	}
	v.body = io.LimitedReader{R: v.rc, N: h.DataSize}
	return h, nil
}

// payload is the current block's declared bytes, bounded by DataSize. A
// decoder handed this cannot read into the following header.
func (v *volume) payload() io.Reader { return &v.body }

// useEncryptedHeaders switches next() to the decrypting header path, once an
// encryption header has yielded a key.
//
// It lives here rather than beside the traversal because "how a header is
// read" is the volume's business, and making it a per-call-site choice is the
// shape this type exists to remove. The key does not carry across a volume
// boundary: a new volume is a new value with hd nil, so header-encrypted
// multi-volume archives fail to parse rather than being misparsed.
func (v *volume) useEncryptedHeaders(key []byte) {
	v.hd = &headerDecrypter{key: key}
}

func (v *volume) Close() error {
	if v.rc == nil {
		return nil
	}
	err := v.rc.Close()
	v.rc = nil
	v.body = io.LimitedReader{}
	return err
}
```

`goimports -w .` in Step 5 drops the `errors` import if nothing in this file uses it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestVolume|TestOpenVolume" -race ./...`
Expected: PASS, all four.

- [ ] **Step 5: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass. The old traversal is untouched and still green.

- [ ] **Step 6: Commit**

```bash
git add volume.go volume_test.go
git commit -m "$(cat <<'EOF'
feat(rarengine): make the stream position a value

Every recurring defect in this traversal had one shape: a block header parsed
out of bytes that were really a previous block's payload. Each fix added a
guard at a site, because "we are at a block boundary" was a fact about the
program's history rather than about any value, and facts about history can
only be maintained by discipline.

volume carries the remaining-payload count, so the fact becomes a property of
a value. next() skips before it reads, which is what makes forgetting
unexpressible rather than merely documented.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `Window` owns solid-history damage

**Files:**
- Modify: `window.go`
- Test: `window_test.go`

**Interfaces:**
- Consumes: existing `Window.Reset`.
- Produces:
  - `func (w *Window) BeginFile(solid bool) error`
  - `func (w *Window) MarkIncomplete()`
  - `ErrSolidStreamBroken` moves from `filereader.go` to `window.go` in Task 12; until then it stays where it is and `window.go` references it.

- [ ] **Step 1: Write the failing test**

Add to `window_test.go`:

```go
func TestWindowBeginFileRefusesSolidAfterIncomplete(t *testing.T) {
	w := NewWindow(0x40000)

	if err := w.BeginFile(false); err != nil {
		t.Fatalf("first BeginFile(false): %v", err)
	}
	w.writeBytes([]byte("hello"))
	w.MarkIncomplete()

	if err := w.BeginFile(true); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("BeginFile(true) after MarkIncomplete = %v, want ErrSolidStreamBroken", err)
	}
}

func TestWindowBeginFileNonSolidClearsIncomplete(t *testing.T) {
	w := NewWindow(0x40000)
	w.MarkIncomplete()

	// A non-solid file resets the history, so nothing it or its successors
	// reference depends on what the damaged file failed to write.
	if err := w.BeginFile(false); err != nil {
		t.Fatalf("BeginFile(false) after MarkIncomplete: %v", err)
	}
	if err := w.BeginFile(true); err != nil {
		t.Fatalf("BeginFile(true) after a clean non-solid file: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run TestWindowBeginFile ./...`
Expected: FAIL with `w.BeginFile undefined`.

- [ ] **Step 3: Write the implementation**

Add to `window.go` — add `incomplete bool` to the `Window` struct with this comment, and the two methods:

```go
	// incomplete records that the history holds something other than what a
	// solid successor's back-references assume: bytes missing because a member
	// ended short, wrong because it failed its CRC32, or absent because a
	// member was refused and never decoded at all.
	//
	// It lives here rather than beside the traversal because that is the
	// question it answers -- is this window still what a solid file may build
	// on. Previously the same state had four writers and a comment warning
	// that a fifth would have to answer the same question they did.
	//
	// The shortfall it describes sits INSIDE what CopyBytes bounds by: a
	// successor reads an earlier member's bytes rather than reading past the
	// written history, so the distance guard cannot catch it.
	incomplete bool
```

```go
// BeginFile prepares the window for a member.
//
// A non-solid member resets the history, so it and everything built on it are
// unaffected by earlier damage -- which is what clears the flag. A solid
// member after damage cannot be decoded correctly and is refused: its
// back-references reach into bytes its predecessors did not write, producing
// plausible-looking output with nothing in the format to mark it.
//
// It returns an error rather than a bool so that errcheck makes handling the
// refusal compulsory rather than customary.
func (w *Window) BeginFile(solid bool) error {
	if solid {
		if w.incomplete {
			return ErrSolidStreamBroken
		}
		w.Reset(true)
		return nil
	}
	w.incomplete = false
	w.Reset(false)
	return nil
}

// MarkIncomplete records that the member just finished left the history in a
// state a solid successor's back-references do not assume.
//
// Called from what happened to the member -- it ended short, or failed its
// checksum, or was refused before decoding -- and never from the error a
// caller received. Those answer different questions: the caller's error asks
// "may traversal continue?", this asks "is the window intact?", and deriving
// one from the other left every non-continuable short member recorded as
// undamaged.
func (w *Window) MarkIncomplete() { w.incomplete = true }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run TestWindow -race ./...`
Expected: PASS.

- [ ] **Step 5: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add window.go window_test.go
git commit -m "$(cat <<'EOF'
feat(window): give the solid-history damage flag one owner

The state answered a question about the window -- is this still what a solid
file may build on -- while living beside the traversal with four writers. It
now lives on the type it describes, with BeginFile as the single entrance and
an error return that makes handling the refusal compulsory.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Lift the crypto primitives into `crypto.go`

Pure move. No behaviour change, no new tests — the existing encryption suite is the proof.

**Files:**
- Create: `crypto.go`
- Modify: `decompressor.go` (remove the moved code)

**Interfaces:**
- Consumes: nothing.
- Produces (unchanged signatures, now in `crypto.go`):
  - `func pbkdf2HmacSha256(password, salt []byte, iter int) ([]byte, []byte)`
  - `func verifyEncCheck(pswCheckVal, encCheck []byte) error`
  - `func newCBCDecryptReader(r io.Reader, key []byte, iv []byte) (io.Reader, error)`
  - `type cbcDecryptReader`

- [ ] **Step 1: Move the code**

Cut `pbkdf2HmacSha256`, `verifyEncCheck`, `cbcDecryptReader` and `newCBCDecryptReader` from `decompressor.go` into a new `crypto.go` with `package rarengine`. **Move the doc comments verbatim** — `cbcDecryptReader.inLen`'s comment records a multi-volume defect and `pbkdf2HmacSha256`'s records why the two 16-iteration loops are not duplication. Losing either re-opens a question that was expensively answered.

Add at the top of `crypto.go`:

```go
// Package-internal cryptographic primitives for RAR5 encryption.
//
// AES key material -- the password, the derived key bytes, and the salt --
// must never appear in an error message or log line produced from this file.
```

- [ ] **Step 2: Verify nothing changed**

Run: `go test -race ./...`
Expected: PASS, including `encrypted_multivolume_test.go` and `verify_password_test.go`.

Run: `git diff --stat`
Expected: `crypto.go` created, `decompressor.go` shrunk by the same count. A net line change means something was edited, not moved.

- [ ] **Step 3: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crypto.go decompressor.go
git commit -m "$(cat <<'EOF'
refactor(rarengine): lift the crypto primitives out of decompressor.go

Pure move ahead of deleting that file. These three are correct and expensively
learned -- cbcDecryptReader's held-back sub-block tail cost a multi-volume
defect to discover -- so they survive the traversal rewrite verbatim rather
than being reimplemented.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `Entry` — one member, one verdict

**Files:**
- Create: `entry.go`
- Test: `entry_test.go`

**Interfaces:**
- Consumes: `FileHeader`, `ErrTruncatedFile`, `ErrCRCMismatch`, `ErrChecksumUnsupported`, `ErrNoActiveFile` (existing, in `filereader.go` until Task 12).
- Produces:
  - `type Entry struct { Header *FileHeader; cur *FileHeader; src io.Reader; size, remaining int64; crc uint32; done error }`
  - `func newEntry(fh *FileHeader, src io.Reader) *Entry`
  - `func terminalEntry(fh *FileHeader, cause error) *Entry`
  - `func (e *Entry) Read(p []byte) (int, error)`
  - `func (e *Entry) Close() error`
  - `func (e *Entry) advanceVolume(fh *FileHeader)`
  - `func (e *Entry) lastBlock() bool`
  - `func (e *Entry) short() bool`

- [ ] **Step 1: Write the failing test**

Create `entry_test.go`:

```go
package rarengine

import (
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

func entryOver(content string, fh *FileHeader) *Entry {
	return newEntry(fh, strings.NewReader(content))
}

func headerFor(content string, withCRC bool) *FileHeader {
	fh := &FileHeader{
		Name:         "f.bin",
		UnpackedSize: int64(len(content)),
		LastBlock:    true,
	}
	if withCRC {
		fh.HasCRC32 = true
		fh.CRC32 = crc32.ChecksumIEEE([]byte(content))
	}
	return fh
}

// A member that delivers its declared size with a matching checksum ends as
// io.EOF, and Close agrees.
func TestEntryCleanReadEndsWithEOF(t *testing.T) {
	const content = "hello world"
	e := entryOver(content, headerFor(content, true))

	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close after clean read = %v, want nil", err)
	}
}

// The verdict must be reachable from Read as well as Close, so a member never
// completes silently whichever way the caller drives it.
func TestEntryCRCMismatchReportedByBothReadAndClose(t *testing.T) {
	const content = "hello world"
	fh := headerFor(content, true)
	fh.CRC32 ^= 0xffffffff // wrong on purpose
	e := entryOver(content, fh)

	_, err := io.Copy(io.Discard, e)
	if !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Read verdict = %v, want ErrCRCMismatch", err)
	}
	if err := e.Close(); !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Close verdict = %v, want ErrCRCMismatch", err)
	}
}

// A source that ends before the declared size is truncation, and truncation
// must never read as a clean end of stream.
func TestEntryTruncationIsNotEOF(t *testing.T) {
	fh := headerFor("hello world", false)
	fh.UnpackedSize = 100 // claims more than the source has
	e := entryOver("hello world", fh)

	_, err := io.Copy(io.Discard, e)
	if !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("verdict = %v, want ErrTruncatedFile", err)
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("ErrTruncatedFile must not satisfy errors.Is(err, io.EOF): " +
			"callers loop until io.EOF, so that restores the silent-truncation bug")
	}
}

// Once a member has failed, it stays failed. A caller told the member is bad
// must not then receive bytes from it.
func TestEntryTerminalErrorIsDurable(t *testing.T) {
	const content = "hello world"
	fh := headerFor(content, true)
	fh.CRC32 ^= 0xffffffff
	e := entryOver(content, fh)

	_, _ = io.Copy(io.Discard, e)

	buf := make([]byte, 8)
	n, err := e.Read(buf)
	if n != 0 {
		t.Fatalf("Read after failure returned %d bytes, want 0", n)
	}
	if !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("Read after failure = %v, want the recorded ErrCRCMismatch", err)
	}
}

// A refused member is still an Entry, so NextEntry's error set stays
// archive-level only.
func TestTerminalEntryReportsItsCause(t *testing.T) {
	fh := &FileHeader{Name: "bomb.bin"}
	e := terminalEntry(fh, ErrRarBombDetected)

	if e.Header != fh {
		t.Fatal("terminal entry must carry the header that names the member")
	}
	buf := make([]byte, 8)
	if _, err := e.Read(buf); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Read = %v, want ErrRarBombDetected", err)
	}
	if err := e.Close(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Close = %v, want ErrRarBombDetected", err)
	}
}

// A zero-length member never enters the read path, so completing it here is
// what gives it a terminal state at all.
func TestEntryZeroLengthCompletes(t *testing.T) {
	e := entryOver("", headerFor("", false))
	n, err := e.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read = (%d, %v), want (0, io.EOF)", n, err)
	}
}

// A header whose declared size is negative -- a 70-bit RAR5 size vint can set
// the sign bit -- must not reach the slice clamp in Read.
func TestEntryNegativeSizeDoesNotPanic(t *testing.T) {
	fh := headerFor("", false)
	fh.UnpackedSize = -1
	e := entryOver("data", fh)

	n, err := e.Read(make([]byte, 8))
	if n != 0 {
		t.Fatalf("Read returned %d bytes for a negative declared size", n)
	}
	if err == nil {
		t.Fatal("Read on a negative declared size must report a verdict")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestEntry|TestTerminalEntry" ./...`
Expected: FAIL with `undefined: newEntry`.

- [ ] **Step 3: Write the implementation**

Create `entry.go`:

```go
package rarengine

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Entry is one member of the archive.
//
// It owns every piece of state belonging to that member: the reader chain its
// bytes come from, the header in force, how many bytes are still owed, the
// running checksum, and whether it has terminated. That state used to be
// spread across three types and mutated from five places, which is what let a
// member end without anyone deciding whether it had ended successfully.
//
// The verdict lives here rather than being returned by the traversal's Next.
// Those are different facts -- "what is the next member" and "how did the
// previous one end" -- and folding both into one return value is what forced
// the traversal to prove, at every failure site, that the stream was still
// positioned. Attached to the member it describes, the verdict needs no such
// proof.
type Entry struct {
	// Header is the FIRST block's header and does not change for the life of
	// the entry, so a caller keeps the header it was handed.
	Header *FileHeader

	// cur is the header in force, which for a multi-volume member is NOT
	// Header: the whole-file CRC32 and UseMac are recorded in the LAST part's
	// header, and LastBlock is what tells the splice a boundary from an end.
	cur *FileHeader

	src       io.Reader
	size      int64
	remaining int64
	crc       uint32

	// done is the terminal state. Once set, every Read returns it and the
	// entry produces nothing further. It is what makes a failure durable
	// rather than something the next Read can erase.
	done error
}

func newEntry(fh *FileHeader, src io.Reader) *Entry {
	return &Entry{
		Header:    fh,
		cur:       fh,
		src:       src,
		size:      fh.UnpackedSize,
		remaining: fh.UnpackedSize,
	}
}

// terminalEntry builds a member that is already finished, carrying cause.
//
// Refusals arrive this way -- a rar bomb, a broken solid run, an unparsable
// file header, an unresolvable password -- so that every per-member outcome
// reaches the caller through the Entry and NextEntry's error set stays
// archive-level only, rather than archive-level-with-exceptions.
func terminalEntry(fh *FileHeader, cause error) *Entry {
	return &Entry{Header: fh, cur: fh, done: cause}
}

// advanceVolume replaces the header in force when the member continues into
// the next volume. It is a named transition rather than a bare field write so
// that the one place allowed to swap the header mid-member stays visible.
func (e *Entry) advanceVolume(fh *FileHeader) { e.cur = fh }

// lastBlock reports whether the header in force marks the member's final
// block, which is how the splice tells a real end from a volume boundary.
func (e *Entry) lastBlock() bool { return e.cur.LastBlock }

// short reports that the member stopped before its declared size.
func (e *Entry) short() bool { return e.remaining > 0 }

// Read produces the member's decompressed bytes, and is the only path that
// advances the byte budget or the running checksum.
func (e *Entry) Read(p []byte) (int, error) {
	// A terminated member yields no further bytes. io.Reader does not forbid a
	// reader from producing data after reporting a failure, and the decoders
	// below are stateful enough that arguing case by case is not worth
	// depending on. Without this those bytes would be appended to a member the
	// caller was already told had failed.
	if e.done != nil {
		return 0, e.done
	}
	if e.src == nil {
		return 0, ErrNoActiveFile
	}
	// Tested with <= rather than ==. The parsers reject a negative declared
	// size and this is the backstop: reaching the clamp below with a negative
	// remaining panics on the slice bound, turning a crafted header into a
	// process kill. A zero-length member also never enters the read path, so
	// completing it here is what gives it a terminal state at all.
	if e.remaining <= 0 {
		return 0, e.finish(nil)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > e.remaining {
		p = p[:e.remaining]
	}

	n, err := e.src.Read(p)
	if n > 0 {
		e.crc = crc32.Update(e.crc, crc32.IEEETable, p[:n])
	}
	e.remaining -= int64(n)

	switch {
	case err == nil && e.remaining == 0:
		return n, e.finish(nil)
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF) && e.remaining > 0:
		return n, e.finish(e.truncated())
	case errors.Is(err, io.EOF):
		return n, e.finish(nil)
	default:
		return n, e.finish(err)
	}
}

// Close finishes the member and returns its verdict.
//
// It does NOT drain packed bytes: volume.next() skips whatever a block
// declared and no one claimed, which is required on paths where no Entry
// exists at all -- service records, unknown block types, refused headers. One
// mechanism moves the stream.
//
// Close is idempotent and returns the same verdict Read did.
func (e *Entry) Close() error {
	if e.done != nil {
		return e.done
	}
	if e.src == nil {
		return e.finish(nil)
	}
	_, err := io.Copy(io.Discard, e)
	if err != nil && !errors.Is(err, io.EOF) {
		return e.done
	}
	if e.done != nil {
		return e.done
	}
	return e.finish(nil)
}

// finish records the terminal state, once, and returns it. Success is recorded
// as io.EOF so that every terminal state is an error value and Read has
// exactly one thing to return.
//
// The first verdict wins and is never overwritten: Read's guard stops bytes
// escaping, this stops a second call downgrading a recorded ErrCRCMismatch to
// io.EOF. The two protect different things.
func (e *Entry) finish(err error) error {
	if e.done != nil {
		return e.done
	}
	if err == nil {
		err = e.verifyChecksum()
	}
	if err == nil {
		err = io.EOF
	}
	e.done = err
	return e.done
}

// verifyChecksum compares the running CRC32 against the header in force at
// completion, which for a multi-volume member is the LAST part's -- that is
// where the whole-file CRC32 is recorded.
func (e *Entry) verifyChecksum() error {
	// UseMac is read from the header that records the digest, which RAR sets
	// only on the last part. Reading it at admission saw the first part's
	// cleared copy and then compared a plaintext CRC32 against a key-derived
	// MAC -- a guaranteed false mismatch on every encrypted multi-volume file.
	//
	// The gate is UseMac and not Encrypted: encryption alone does not make a
	// digest uncheckable, and RAR says so by setting this flag. Gating on
	// Encrypted would hand the archive a bit that switches verification off.
	if e.cur.UseMac {
		return fmt.Errorf("%w: file %q", ErrChecksumUnsupported, e.cur.Name)
	}
	// Gated on the produced size, which this type enforces, rather than on
	// IsDir, which the archive asserts and nothing cross-checks. An entry that
	// produced bytes is verified whatever it calls itself; one that produced
	// none has nothing to verify.
	if e.size == 0 || !e.cur.HasCRC32 {
		return nil
	}
	if e.crc != e.cur.CRC32 {
		return fmt.Errorf("%w: file %q: computed=%08x header=%08x",
			ErrCRCMismatch, e.cur.Name, e.crc, e.cur.CRC32)
	}
	return nil
}

func (e *Entry) truncated() error {
	return fmt.Errorf("%w: file %q: got %d of %d bytes",
		ErrTruncatedFile, e.cur.Name, e.size-e.remaining, e.size)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestEntry|TestTerminalEntry" -race ./...`
Expected: PASS, all seven.

- [ ] **Step 5: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add entry.go entry_test.go
git commit -m "$(cat <<'EOF'
feat(rarengine): give each member ownership of its own verdict

Next() returned either the next header or the previous member's verdict, and
that conflation is why FileError had to promise the stream was positioned and
prove it at every failure site. Attached to the member it describes, the
verdict needs no such promise.

Delivered by both Read and Close so a member never completes silently
whichever way the caller drives it. A refused member is a terminal Entry
rather than a returned error, which is what lets the traversal's error set be
archive-level only.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `Reader` — traversal, dispatch and admission

Single-volume, unencrypted. Multi-volume comes in Task 9, encryption in Task 10.

**Files:**
- Create: `reader.go`
- Test: `reader_test.go`

**Interfaces:**
- Consumes: `volume` (Task 4), `Window.BeginFile` (Task 5), `Entry`/`newEntry`/`terminalEntry` (Task 7), `storeReader`/`lz50Reader`/`decoder50` (existing, in `decompressor.go`/`engine_rar5.go` until Task 12).
- Produces:
  - `type Reader struct { ... }`
  - `func NewReader(volumes <-chan io.ReadCloser) *Reader`
  - `func (r *Reader) Reset(volumes <-chan io.ReadCloser)`
  - `func (r *Reader) SetPasswords(candidates []string)`
  - `func (r *Reader) NextEntry() (*Entry, error)`
  - `func (r *Reader) nextVolume() error`
  - `func (r *Reader) buildChain(fh *FileHeader, src io.Reader) (io.Reader, error)` — extended in Task 10

- [ ] **Step 1: Write the failing test**

Create `reader_test.go`:

```go
package rarengine

import (
	"errors"
	"io"
	"testing"
)

// The whole point of the rewrite, asserted end to end: a fabricated file entry
// planted in an unclaimed block's payload must never be returned as a member.
func TestNextEntrySkipsFabricatedHeaderInPayload(t *testing.T) {
	planted := fabricatedRAR5()
	archive := rar5BlockDeclaring(HeaderTypeArchive, len(planted), nil, true)
	stream := append(append([]byte{}, archive...), planted...)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err == nil {
		t.Fatalf("NextEntry returned member %q, which exists nowhere in the "+
			"archive -- it was parsed out of the archive header's payload",
			e.Header.Name)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("NextEntry error = %v, want io.EOF or ErrNoNextVolume", err)
	}
}

// A rar bomb is refused as a terminal Entry, not as an error from NextEntry.
func TestRarBombIsRefusedAsTerminalEntry(t *testing.T) {
	r := NewReader(volumesOf(rarBombArchive(t)))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if err := e.Close(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Close = %v, want ErrRarBombDetected", err)
	}
}

// A member whose file header does not parse is skipped, and the archive stays
// readable past it. Under the old design this ended the traversal, because
// nothing could say where the stream was.
func TestUnparsableFileHeaderDoesNotEndTraversal(t *testing.T) {
	stream := archiveWithBadFileHeaderThen(t, "good.bin", "payload")

	r := NewReader(volumesOf(stream))
	for {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("traversal ended before reaching the good member: %v", err)
		}
		if e.Header != nil && e.Header.Name == "good.bin" {
			_ = e.Close()
			return
		}
		_ = e.Close()
	}
}

// A solid member following a damaged one is refused rather than decoded
// against history its predecessor never wrote.
func TestSolidMemberAfterDamageIsRefused(t *testing.T) {
	r := NewReader(volumesOf(truncatedThenSolidArchive(t)))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("first member verdict = %v, want ErrTruncatedFile", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if err := second.Close(); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor verdict = %v, want ErrSolidStreamBroken", err)
	}
}
```

Add this shared fixture builder to `reader_test.go`. Tasks 9 and 11 use it too. It constructs archives by hand because the property under test is what happens to a *crafted* archive.

Field order mirrors `ParseFileHeader` at `header.go:460` exactly — file flags, unpacked size, attributes, optional mtime, optional CRC32, compression flags, host OS, name length, name. An incorrect builder produces a test that passes against broken code, which is why Step 4 round-trips every fixture through the real parser before anything relies on it.

```go
// memberSpec describes one stored (method 0) RAR5 member. The zero value is an
// ordinary single-block member: notFirst and notLast are negative so that the
// common case needs no fields set.
type memberSpec struct {
	name    string
	content string

	// unpackedSz and packedSz default to len(content). Set them to make the
	// header lie about the size, which is how the bomb and truncation
	// fixtures are built.
	unpackedSz int64
	packedSz   int64

	solid   bool
	isDir   bool
	withCRC bool

	notFirst bool // clears FirstBlock: this is a continuation block
	notLast  bool // clears LastBlock: the member continues in the next volume

	// badName declares a longer name than the header carries, so
	// ParseFileHeader fails its bounds check while the BLOCK header stays
	// CRC-valid. That is the case the traversal must skip rather than stop on.
	badName bool
}

// rar5Member builds one RAR5 file block followed by its payload.
func rar5Member(t testing.TB, s memberSpec) []byte {
	t.Helper()
	content := []byte(s.content)

	unpacked := s.unpackedSz
	if unpacked == 0 {
		unpacked = int64(len(content))
	}
	packed := s.packedSz
	if packed == 0 {
		packed = int64(len(content))
	}

	var fileFlags uint64
	if s.isDir {
		fileFlags |= FileFlagIsDir
	}
	if s.withCRC {
		fileFlags |= FileFlagHasCRC32
	}

	var f bytes.Buffer
	f.Write(EncodeVint(fileFlags))
	f.Write(EncodeVint(uint64(unpacked)))
	f.Write(EncodeVint(0)) // attributes
	if s.withCRC {
		var crcBuf [4]byte
		binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(content))
		f.Write(crcBuf[:])
	}
	// Compression flags: method lives in bits 7..9, so zero is store (method
	// 0). FileCompSolid is bit 6.
	var compFlags uint64
	if s.solid {
		compFlags |= FileCompSolid
	}
	f.Write(EncodeVint(compFlags))
	f.Write(EncodeVint(0)) // host OS

	name := []byte(s.name)
	if s.badName {
		f.Write(EncodeVint(uint64(len(name) + 16)))
	} else {
		f.Write(EncodeVint(uint64(len(name))))
	}
	f.Write(name)

	blockFlags := uint64(HeaderFlagHasData)
	if s.notFirst {
		blockFlags |= HeaderFlagDataNotFirst
	}
	if s.notLast {
		blockFlags |= HeaderFlagDataNotLast
	}

	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeFile))
	p.Write(EncodeVint(blockFlags))
	p.Write(EncodeVint(uint64(packed)))
	p.Write(f.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(p.Bytes()))
	out.Write(content)
	return out.Bytes()
}

// rar5Archive concatenates the RAR5 signature, an archive header, and each
// member, producing one volume's bytes.
func rar5Archive(t testing.TB, solid bool, members ...[]byte) []byte {
	t.Helper()
	var arc bytes.Buffer
	arc.Write(EncodeVint(HeaderTypeArchive))
	arc.Write(EncodeVint(0))
	var arcFlags uint64
	if solid {
		arcFlags |= ArcFlagSolid
	}
	arc.Write(EncodeVint(arcFlags))

	var out bytes.Buffer
	out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	out.Write(rar5Block(arc.Bytes()))
	for _, m := range members {
		out.Write(m)
	}
	return out.Bytes()
}

func rarBombArchive(t testing.TB) []byte {
	return rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       "bomb.bin",
		content:    "x",
		unpackedSz: 2 << 30, // 2 GiB declared
		packedSz:   1,       // from 1 byte packed
	}))
}

func archiveWithBadFileHeaderThen(t testing.TB, name, content string) []byte {
	return rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "bad.bin", content: "junkjunk", badName: true}),
		rar5Member(t, memberSpec{name: name, content: content, withCRC: true}),
	)
}

func truncatedThenSolidArchive(t testing.TB) []byte {
	return rar5Archive(t, true,
		// Declares 100 bytes of output but carries 5, so it ends short.
		rar5Member(t, memberSpec{name: "short.bin", content: "short", unpackedSz: 100}),
		rar5Member(t, memberSpec{name: "solid.bin", content: "after", solid: true, withCRC: true}),
	)
}
```

Verify `ArcFlagSolid`'s name before using it — run `grep -n "ArcFlag" header.go` and substitute the actual constant. If the archive header carries no solid flag in this parser, set `solid` on the member headers alone and drop the parameter.

Add this round-trip test, which must pass before any fixture is trusted:

```go
func TestFixtureBuildersRoundTrip(t *testing.T) {
	blk := rar5Member(t, memberSpec{name: "f.bin", content: "hello", withCRC: true})

	h, err := ReadBlockHeader(bytes.NewReader(blk))
	if err != nil {
		t.Fatalf("builder produced an unreadable block: %v", err)
	}
	fh, err := ParseFileHeader(h)
	if err != nil {
		t.Fatalf("builder produced an unparsable file header: %v", err)
	}
	if fh.Name != "f.bin" || fh.UnpackedSize != 5 {
		t.Fatalf("round trip = %q/%d, want f.bin/5", fh.Name, fh.UnpackedSize)
	}
	if !fh.FirstBlock || !fh.LastBlock {
		t.Fatalf("default member should be a single block, got first=%v last=%v",
			fh.FirstBlock, fh.LastBlock)
	}
	if !fh.HasCRC32 || fh.CRC32 != crc32.ChecksumIEEE([]byte("hello")) {
		t.Fatal("builder wrote the wrong CRC32")
	}

	bad := rar5Member(t, memberSpec{name: "bad.bin", content: "junk", badName: true})
	bh, err := ReadBlockHeader(bytes.NewReader(bad))
	if err != nil {
		t.Fatalf("badName fixture must keep a CRC-valid BLOCK header: %v", err)
	}
	if _, err := ParseFileHeader(bh); err == nil {
		t.Fatal("badName fixture must fail ParseFileHeader, or the test it " +
			"backs proves nothing")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestNextEntry|TestRarBomb|TestUnparsable|TestSolidMember|TestFixtureBuilders" ./...`
Expected: FAIL with `undefined: NewReader`.

- [ ] **Step 3: Write the implementation**

Create `reader.go`:

```go
package rarengine

import (
	"errors"
	"io"
)

// Reader is a sequential, tar-like reader over a RAR5 archive delivered as a
// channel of volumes.
//
// It owns the volume chain and block dispatch. It does NOT own where the
// stream is -- volume does -- and it does not own how a member ended -- Entry
// does. What is left here is genuinely traversal: which volume, which block,
// and whether a member may begin.
type Reader struct {
	volumes <-chan io.ReadCloser

	// vol is nil whenever no volume is open, including after every failure.
	// Because an advance constructs a new volume rather than repointing one, a
	// failed advance cannot leave a partially consumed volume reachable.
	vol *volume

	win   *Window
	entry *Entry
	dec50 *decoder50

	passwords []string
	// resolved is the candidate that verified against the archive's check
	// value, latched so the cost is one derivation per candidate per archive
	// rather than per member.
	resolved    string
	hasResolved bool

	// solid reports whether the archive header declared a solid archive. It
	// decides whether abandoning a member must decode its remainder to keep
	// the window valid for a successor -- see NextEntry.
	solid bool
}

func NewReader(volumes <-chan io.ReadCloser) *Reader {
	return &Reader{
		volumes: volumes,
		win:     NewWindow(32 * 1024 * 1024),
		dec50:   newDecoder50(),
	}
}

// Reset reconfigures the reader for a new archive, reusing the 32 MB window.
// Nothing else survives: a verdict, a resolved password and a damaged window
// all belong to the archive that produced them.
func (r *Reader) Reset(volumes <-chan io.ReadCloser) {
	if r.vol != nil {
		_ = r.vol.Close()
		r.vol = nil
	}
	r.volumes = volumes
	r.entry = nil
	r.resolved, r.hasResolved = "", false
	r.solid = false
	r.win.Reset(false)
	r.win.incomplete = false
}

// SetPasswords supplies candidate passwords, tried in order against the
// archive's password check value. RAR5 only.
func (r *Reader) SetPasswords(candidates []string) { r.passwords = candidates }

// NextEntry finishes any active entry, scans forward, and returns the next
// member. io.EOF reports that the archive is over.
//
// Its errors are archive-level only -- a malformed block header, no next
// volume, an unsupported format, end of stream. Every per-member outcome is
// delivered by the Entry, including refusals, which arrive as an Entry that is
// already terminal.
func (r *Reader) NextEntry() (*Entry, error) {
	if err := r.finishActive(); err != nil {
		return nil, err
	}
	for {
		if r.vol == nil {
			if err := r.nextVolume(); err != nil {
				return nil, err
			}
		}
		h, err := r.vol.next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				_ = r.vol.Close()
				r.vol = nil
				continue
			}
			return nil, err
		}
		e, err := r.dispatch(h)
		if err != nil {
			return nil, err
		}
		if e != nil {
			return e, nil
		}
	}
}

// finishActive ends the member in progress before the traversal moves on.
//
// Abandoning a member costs a decode only when the archive is solid, because
// that is the only case where a successor's back-references reach into what
// this member should have written. In a non-solid archive volume.next() skips
// the raw packed bytes instead, which is why listing an archive's members no
// longer decompresses it.
//
// Either way a member that did not reach its declared size marks the window
// incomplete, so a solid successor is refused rather than decoded against
// history nobody wrote.
func (r *Reader) finishActive() error {
	e := r.entry
	r.entry = nil
	if e == nil {
		return nil
	}
	if r.solid {
		_ = e.Close()
	}
	if e.short() || (e.done != nil && !errors.Is(e.done, io.EOF) &&
		!errors.Is(e.done, ErrChecksumUnsupported)) {
		r.win.MarkIncomplete()
	}
	return nil
}

// dispatch consumes one block and reports what it was.
//
// A nil Entry with a nil error means the block held nothing the caller wants
// and scanning continues. Nothing here discards payload: volume.next() does
// that on the way to the following header, unconditionally, whether or not any
// case below looked at the block.
func (r *Reader) dispatch(h *BlockHeader) (*Entry, error) {
	switch h.Type {
	case HeaderTypeArchive:
		ah, err := ParseArchiveHeader(h)
		if err != nil {
			return nil, nil // the block is skipped; the archive may still parse
		}
		r.solid = r.solid || ah.Solid
		return nil, nil

	case HeaderTypeFile:
		fh, err := ParseFileHeader(h)
		if err != nil {
			// Skipped rather than terminal. Under the previous design nothing
			// could say where the stream was after a failed parse, so this
			// ended the traversal; volume.next() answers that now.
			return nil, nil
		}
		// A continuation block belongs to a member already announced. Reaching
		// one here means that member was abandoned, so it is skipped like any
		// other unclaimed block.
		if !fh.FirstBlock {
			return nil, nil
		}
		if fh.UnpackedSize > 1024*1024 && fh.UnpackedSize > 1000*fh.PackedSize {
			r.win.MarkIncomplete()
			return terminalEntry(fh, ErrRarBombDetected), nil
		}
		if err := r.win.BeginFile(fh.Solid); err != nil {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err), nil
		}
		src, err := r.buildChain(fh, r.vol.payload())
		if err != nil {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err), nil
		}
		e := newEntry(fh, src)
		r.entry = e
		return e, nil

	default:
		// Everything the caller never sees, including service records -- quick
		// open, comment, recovery, ACL, stream. Those reuse the file-header
		// layout, so routing them to the file case would surface one as a
		// member named after the record and hand its bytes over as content.
		return nil, nil
	}
}

// buildChain assembles the decode chain for a member. Extended in Task 10 to
// insert decryption below the multi-volume splice.
func (r *Reader) buildChain(fh *FileHeader, src io.Reader) (io.Reader, error) {
	if fh.Method == 0 {
		return &storeReader{r: src, win: r.win}, nil
	}
	r.dec50.init(src, fh.FirstBlock)
	return &lz50Reader{dec: r.dec50, win: r.win}, nil
}

// nextVolume closes the current volume and opens the next.
//
// Every failure leaves r.vol nil, which is a lifetime rather than a rule: the
// field is assigned the result, so a failed advance has nothing to leave
// behind. Under the previous design this had to be maintained by hand at each
// exit, and a volume left standing after a failure was read again at whatever
// offset the failure stopped at.
func (r *Reader) nextVolume() error {
	if r.vol != nil {
		_ = r.vol.Close()
		r.vol = nil
	}
	rc, ok := <-r.volumes
	if !ok {
		return ErrNoNextVolume
	}
	v, err := openVolume(rc)
	if err != nil {
		_ = rc.Close()
		return err
	}
	r.vol = v
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestNextEntry|TestRarBomb|TestUnparsable|TestSolidMember|TestFixtureBuilders" -race ./...`
Expected: PASS.

- [ ] **Step 5: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass. The old traversal is untouched and still green.

- [ ] **Step 6: Commit**

```bash
git add reader.go reader_test.go
git commit -m "$(cat <<'EOF'
feat(rarengine): add the traversal over volume and Entry

What is left in the traversal once position and verdict are owned elsewhere is
genuinely traversal: which volume, which block, and whether a member may
begin. No case discards payload, because volume.next() does that on the way to
the following header whether or not any case looked at the block -- so the
switch that three separate changes forgot to maintain has nothing left to
forget.

An unparsable file header is now skipped rather than ending the traversal. It
was terminal only because nothing could say where the stream was.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Multi-volume splicing and the continuation guard

**Files:**
- Create: `splice.go`
- Modify: `reader.go`
- Test: `splice_test.go`

**Interfaces:**
- Consumes: `Reader`, `Entry`, `volume`.
- Produces:
  - `type volumeSplicer struct { r *Reader; e *Entry; src io.Reader }` (renamed to `multiVolumePayloadReader` in Task 12, once the old one is gone)
  - `func (r *Reader) nextVolumePayload(e *Entry) (io.Reader, error)`

- [ ] **Step 1: Write the failing test**

Create `splice_test.go`:

```go
package rarengine

import (
	"errors"
	"io"
	"testing"
)

// A member split across two volumes reads as one continuous stream.
func TestMemberSplicesAcrossVolumes(t *testing.T) {
	v1, v2, want := storedMemberSplitAcrossVolumes(t, "split.bin", "hello world")

	r := NewReader(volumesOf(v1, v2))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
}

// The defect this fixes: a continuation claiming encryption when the first
// block did not had that volume's ciphertext spliced in and delivered verbatim
// as content, with Encrypted reported false. PR #44 fixed the same hole for
// RAR3 and it was never applied to RAR5.
func TestContinuationEncryptionMismatchIsRefused(t *testing.T) {
	v1, v2 := memberWhoseContinuationClaimsEncryption(t, "sneaky.bin")

	r := NewReader(volumesOf(v1, v2))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.Encrypted {
		t.Fatal("fixture is wrong: the FIRST block must declare plaintext")
	}

	_, readErr := io.Copy(io.Discard, e)
	if !errors.Is(readErr, ErrCorruptFileHeader) {
		t.Fatalf("verdict = %v, want ErrCorruptFileHeader -- the continuation "+
			"claims encryption the first block did not, so its bytes would be "+
			"delivered undecrypted as content", readErr)
	}
}

// A member abandoned mid-file leaves continuation blocks on later volumes.
// Reaching the next real member must skip all of them.
func TestAbandonedMultiVolumeMemberIsSkippedToNextEntry(t *testing.T) {
	v1, v2 := splitMemberThenSecondMember(t, "big.bin", "second.bin")

	r := NewReader(volumesOf(v1, v2))
	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if first.Header.Name != "big.bin" {
		t.Fatalf("first member = %q, want big.bin", first.Header.Name)
	}
	// Deliberately read nothing.

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if second.Header.Name != "second.bin" {
		t.Fatalf("second member = %q, want second.bin -- the abandoned "+
			"member's continuation blocks were not skipped", second.Header.Name)
	}
}
```

Add these builders to `splice_test.go`, on top of `rar5Member` / `rar5Archive` from Task 8. A split member's first block sets `notLast`; its continuation sets `notFirst`. The whole-file CRC32 goes on the **last** part, because that is where RAR records it and where `Entry.verifyChecksum` reads it from.

```go
// storedMemberSplitAcrossVolumes returns two volumes carrying one member whose
// content is split between them, plus the content it should reassemble to.
func storedMemberSplitAcrossVolumes(t testing.TB, name, content string) (v1, v2 []byte, want string) {
	t.Helper()
	half := len(content) / 2
	first, second := content[:half], content[half:]

	v1 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       name,
		content:    first,
		unpackedSz: int64(len(content)), // the WHOLE member's output size
		packedSz:   int64(len(first)),   // this part's packed bytes
		notLast:    true,
	}))
	v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       name,
		content:    second,
		unpackedSz: int64(len(content)),
		packedSz:   int64(len(second)),
		notFirst:   true,
		withCRC:    true, // whole-file CRC32 lives on the last part
	}))
	return v1, v2, content
}

// splitMemberThenSecondMember returns two volumes: the first opens a member
// that continues into the second, where a further member follows it.
func splitMemberThenSecondMember(t testing.TB, splitName, secondName string) (v1, v2 []byte) {
	t.Helper()
	v1 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name: splitName, content: "aaaa", unpackedSz: 8, packedSz: 4, notLast: true,
	}))
	v2 = rar5Archive(t, false,
		rar5Member(t, memberSpec{
			name: splitName, content: "bbbb", unpackedSz: 8, packedSz: 4,
			notFirst: true, withCRC: true,
		}),
		rar5Member(t, memberSpec{name: secondName, content: "second", withCRC: true}),
	)
	return v1, v2
}
```

`memberWhoseContinuationClaimsEncryption` cannot be built with `rar5Member` alone: `fh.Encrypted` is set from an encryption **extra record**, which `rar5Member` does not write. Build it the other way round, which needs no new fixture machinery — take an encrypted multi-volume member's real first volume and give it a hand-built *plaintext* continuation:

```go
// memberWhoseContinuationClaimsEncryption returns a first volume whose member
// declares encryption and a second whose continuation of it does not.
//
// The guard is symmetric -- it compares the two claims -- so this direction
// exercises the same check as the plaintext-then-encrypted one, and needs no
// hand-built encryption extra record. Reversing it would mean synthesising
// that record; see parseExtraRecords in header.go if that is ever wanted.
func memberWhoseContinuationClaimsEncryption(t testing.TB, name string) (v1, v2 []byte) {
	t.Helper()
	// Volume 1 of the existing encrypted multi-volume fixture. Locate it with:
	//   grep -rn "testdata" encrypted_multivolume_test.go
	v1 = readFixtureVolume(t, 1)
	v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name: name, content: "plaintext-continuation", notFirst: true, withCRC: true,
	}))
	return v1, v2
}
```

Adjust `TestContinuationEncryptionMismatchIsRefused` to match this direction: assert `e.Header.Encrypted` is **true** on the first block, set `SetPasswords` with the fixture's password, and expect `ErrCorruptFileHeader` from the read. Verify every hand-built fixture through `ParseFileHeader` as in Task 8's round-trip test before relying on it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestMemberSplices|TestContinuation|TestAbandonedMulti" ./...`
Expected: FAIL — the first with a short read, since `buildChain` currently hands the entry a single volume's payload.

- [ ] **Step 3: Write the implementation**

Create `splice.go`:

```go
package rarengine

import (
	"fmt"
	"io"
)

// volumeSplicer presents a member's payload as one continuous stream across
// the volumes it spans.
//
// It sits BELOW decryption in the chain, not above it. A member's ciphertext
// is one continuous CBC stream that volume boundaries cut at arbitrary
// offsets, with no per-volume IV to restart from -- the header repeats the
// first part's salt and IV unchanged. Splicing above the decryption fed each
// new volume's raw bytes straight to the decoder, so the first part decoded
// and every part after it was ciphertext.
type volumeSplicer struct {
	r   *Reader
	e   *Entry
	src io.Reader
}

func (s *volumeSplicer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := s.src.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			// The header in force says whether this is the member's final
			// block; anything else means the payload continues in the next
			// volume, so an inner EOF is a boundary rather than an end.
			if s.e.lastBlock() {
				return 0, io.EOF
			}
			next, nextErr := s.r.nextVolumePayload(s.e)
			if nextErr != nil {
				return 0, nextErr
			}
			s.src = next
			continue
		}
		return 0, err
	}
}

// nextVolumePayload advances to the volume holding the member's continuation
// and returns its payload.
//
// It scans past whatever the new volume opens with -- its own archive header,
// service records -- because volume.next() skips each block's declared payload
// on the way to the following header. Nothing here has to discard.
func (r *Reader) nextVolumePayload(e *Entry) (io.Reader, error) {
	if err := r.nextVolume(); err != nil {
		return nil, err
	}
	for {
		h, err := r.vol.next()
		if err != nil {
			return nil, err
		}
		if h.Type != HeaderTypeFile {
			if h.Type == HeaderTypeArchive {
				if ah, aerr := ParseArchiveHeader(h); aerr == nil {
					r.solid = r.solid || ah.Solid
				}
			}
			continue
		}
		fh, err := ParseFileHeader(h)
		if err != nil {
			return nil, err
		}
		if fh.FirstBlock {
			// A new member where a continuation was expected: the member in
			// progress has no more parts, so it ended short.
			return nil, io.EOF
		}
		// A per-file header flag must be re-checked on every volume advance,
		// not only at admission. This path builds no chain -- it feeds bytes
		// into the one the first block established -- so a continuation
		// claiming encryption the first block did not had this volume's
		// ciphertext delivered verbatim as content, with a nil error and a
		// header reporting Encrypted false. The inverse decrypts bytes that
		// were never ciphertext.
		if fh.Encrypted != e.Header.Encrypted {
			return nil, fmt.Errorf("%w: file %q: continuation declares "+
				"Encrypted=%v, first block declared %v",
				ErrCorruptFileHeader, e.Header.Name, fh.Encrypted, e.Header.Encrypted)
		}
		// Captures the whole-file CRC32, LastBlock and UseMac, all of which
		// RAR records on the LAST part rather than the first.
		e.advanceVolume(fh)
		return r.vol.payload(), nil
	}
}
```

In `reader.go`, wrap the payload in the splicer before building the chain. Replace the `buildChain` call site in `dispatch` with:

```go
		e := &Entry{Header: fh, cur: fh, size: fh.UnpackedSize, remaining: fh.UnpackedSize}
		splicer := &volumeSplicer{r: r, e: e, src: r.vol.payload()}
		src, err := r.buildChain(fh, splicer)
		if err != nil {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err), nil
		}
		e.src = src
		r.entry = e
		return e, nil
```

The `Entry` is constructed before the splicer because the splicer consults it through `lastBlock()` while reading, so both must exist before the first `Read`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestMemberSplices|TestContinuation|TestAbandonedMulti" -race ./...`
Expected: PASS.

- [ ] **Step 5: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add splice.go reader.go splice_test.go
git commit -m "$(cat <<'EOF'
feat(rarengine): splice members across volumes, and check the continuation

Also fixes a live defect. PR #44 established that a per-file header flag must
be re-checked on every volume advance and applied it to RAR3; RAR5's
continuation path never got the same treatment. Because that path builds no
chain -- it feeds bytes into the one the first block established -- a member
whose continuation claimed encryption had that volume's ciphertext delivered
verbatim as content, with a nil error and a header reporting Encrypted false.

The severity is integrity rather than disclosure: the archive already controls
those bytes and their CRC32. What it bought was making this library report
Encrypted false over content it did not decrypt.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Encryption — resolve a password, build the chain

**Files:**
- Modify: `reader.go`
- Test: `reader_encryption_test.go`

**Interfaces:**
- Consumes: `pbkdf2HmacSha256`, `verifyEncCheck`, `newCBCDecryptReader` (Task 6), `VerifyFilePassword`, `ParseCryptHeader`, `headerKeyFromPassword` (existing).
- Produces:
  - `func (r *Reader) resolvePassword(fh *FileHeader) (string, error)`
  - `Reader.buildChain` extended to insert `cbcDecryptReader` below the splice.
  - `HeaderTypeEncryption` case in `dispatch`.

- [ ] **Step 1: Write the failing test**

Create `reader_encryption_test.go`:

```go
package rarengine

import (
	"errors"
	"io"
	"testing"
)

// The list is tried in order and the right one wins, without the caller
// re-running the archive per candidate.
func TestSetPasswordsResolvesFromCandidateList(t *testing.T) {
	vols := encryptedFixtureVolumes(t) // testdata encrypted RAR5 fixture

	r := NewReader(vols)
	r.SetPasswords([]string{"wrong-one", "wrong-two", encryptedFixturePassword})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read encrypted member: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
}

// No candidate matching is a per-member outcome, not an archive-level error.
func TestNoMatchingPasswordIsATerminalEntry(t *testing.T) {
	r := NewReader(encryptedFixtureVolumes(t))
	r.SetPasswords([]string{"nope"})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if err := e.Close(); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Close = %v, want ErrWrongPassword", err)
	}
}

// An empty candidate list on an encrypted member is "password required", which
// a caller may act on by prompting.
func TestNoPasswordsSuppliedReportsPasswordRequired(t *testing.T) {
	r := NewReader(encryptedFixtureVolumes(t))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if err := e.Close(); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("Close = %v, want ErrPasswordRequired", err)
	}
}
```

`encryptedFixtureVolumes` and `encryptedFixturePassword` come from the existing encrypted fixtures. Find them first:

Run: `grep -rn "password\|Password" encrypted_multivolume_test.go | head -20 && ls testdata | grep -i "enc\|pass"`

Reuse the existing fixture and its password rather than generating new ones — those fixtures were built against real `rar` output and are the only proof the KDF matches the reference implementation.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestSetPasswords|TestNoMatchingPassword|TestNoPasswordsSupplied" ./...`
Expected: FAIL — `SetPasswords` exists but nothing consumes it, so the member decodes ciphertext.

- [ ] **Step 3: Write the implementation**

Add to `reader.go`:

```go
// resolvePassword picks the candidate that matches the member's password check
// value, latching it for the rest of the archive.
//
// The check value is a fold of the PBKDF2 chain, so a candidate is tested
// without decrypting or decompressing anything. Latching means the cost is one
// derivation per candidate per archive rather than per member.
//
// An archive carrying no check value cannot have a candidate verified this
// way. The first candidate is used and a wrong one surfaces as
// ErrCRCMismatch -- re-running the archive per candidate would mean re-reading
// every volume, and modern RAR stores a check value by default.
func (r *Reader) resolvePassword(fh *FileHeader) (string, error) {
	if r.hasResolved {
		return r.resolved, nil
	}
	if len(r.passwords) == 0 {
		return "", ErrPasswordRequired
	}
	if fh.EncCheck == nil {
		r.resolved, r.hasResolved = r.passwords[0], true
		return r.resolved, nil
	}
	for _, candidate := range r.passwords {
		ok, hasCheck, err := VerifyFilePassword(fh, candidate)
		if err != nil {
			return "", err
		}
		if !hasCheck {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
		if ok {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
	}
	return "", ErrWrongPassword
}
```

Replace `buildChain`:

```go
// buildChain assembles the decode chain for a member:
//
//	decoder50 / storeReader
//	  └─ cbcDecryptReader (if encrypted)
//	       └─ volumeSplicer
//
// Decryption sits BELOW the splice so one CBC reader carries its chaining
// state across a volume boundary; see volumeSplicer for why that matters.
func (r *Reader) buildChain(fh *FileHeader, src io.Reader) (io.Reader, error) {
	if fh.Encrypted {
		password, err := r.resolvePassword(fh)
		if err != nil {
			return nil, err
		}
		const maxKdfCount = 24
		if fh.KdfCount > maxKdfCount {
			return nil, errKdfCountExceeded(fh.KdfCount, maxKdfCount)
		}
		key, pswCheckVal := pbkdf2HmacSha256([]byte(password), fh.Salt, 1<<fh.KdfCount)
		if fh.EncCheck != nil {
			if err := verifyEncCheck(pswCheckVal, fh.EncCheck); err != nil {
				return nil, err
			}
		}
		decSrc, err := newCBCDecryptReader(src, key, fh.IV)
		if err != nil {
			return nil, err
		}
		src = decSrc
	}
	if fh.Method == 0 {
		return &storeReader{r: src, win: r.win}, nil
	}
	r.dec50.init(src, fh.FirstBlock)
	return &lz50Reader{dec: r.dec50, win: r.win}, nil
}
```

Add the encryption-header case to `dispatch`, before `default`:

```go
	case HeaderTypeEncryption:
		ch, err := ParseCryptHeader(h)
		if err != nil {
			return nil, nil
		}
		password, err := r.resolveHeaderPassword(ch)
		if err != nil {
			// Every header after this one is ciphertext, so there is no member
			// to name and nothing to continue to. Archive-level.
			return nil, err
		}
		key, err := headerKeyFromPassword(ch, password)
		if err != nil {
			return nil, err
		}
		r.vol.useEncryptedHeaders(key)
		return nil, nil
```

And the header-side resolver:

```go
// resolveHeaderPassword is resolvePassword for archive-level header
// encryption, whose check value lives on the CryptHeader rather than on a file
// header.
func (r *Reader) resolveHeaderPassword(ch *CryptHeader) (string, error) {
	if r.hasResolved {
		return r.resolved, nil
	}
	if len(r.passwords) == 0 {
		return "", ErrPasswordRequired
	}
	for _, candidate := range r.passwords {
		ok, hasCheck, err := VerifyPassword(ch, candidate)
		if err != nil {
			return "", err
		}
		if !hasCheck || ok {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
	}
	return "", ErrWrongPassword
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestSetPasswords|TestNoMatchingPassword|TestNoPasswordsSupplied" -race ./...`
Expected: PASS.

- [ ] **Step 5: Verify against the encrypted multi-volume fixtures**

Run: `go test -run "Encrypted" -race ./...`
Expected: PASS. These are the fixtures that caught the CBC held-back-tail defect; a failure here means the splice/decrypt ordering is wrong.

- [ ] **Step 6: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add reader.go reader_encryption_test.go
git commit -m "$(cat <<'EOF'
feat(rarengine): resolve a password from a candidate list

gonzbd holds a list of candidate passwords and had to re-run the whole archive
per candidate, reopening every volume, because the library accepted one. The
check value is a fold of the PBKDF2 chain, so a candidate can be tested
without decrypting or decompressing anything -- and latching the winner makes
the cost one derivation per candidate per archive rather than per member.

This also deletes errorReader, whose only purpose was smuggling a deferred
password failure into the read path. With the password resolved at admission
those are terminal entries like every other refusal.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Prove the cheap-abandon path

No new production code — Task 8's `finishActive` already implements it. This task pins the behaviour so a later change cannot quietly restore the decompress-to-skip cost.

**Files:**
- Test: `reader_abandon_test.go`

**Interfaces:**
- Consumes: `Reader.finishActive` (Task 8).
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Create `reader_abandon_test.go`:

```go
package rarengine

import (
	"errors"
	"io"
	"testing"
)

// countingReadCloser reports how many bytes were actually read from a volume.
type countingReadCloser struct {
	r io.Reader
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
func (c *countingReadCloser) Close() error { return nil }

// Listing an archive's members must not decompress them. Under the previous
// design advancing past a member decoded and discarded its content, which is
// why gonzbd's InspectRar5 decompressed an entire archive to read its
// filenames.
func TestListingNonSolidArchiveDoesNotDecompress(t *testing.T) {
	stream := nonSolidArchiveWithCompressedMembers(t)

	r := NewReader(volumesOf(stream))
	var names []string
	for {
		e, err := r.NextEntry()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				break
			}
			t.Fatalf("NextEntry: %v", err)
		}
		names = append(names, e.Header.Name)
		// Deliberately never read the member.
	}
	if len(names) < 2 {
		t.Fatalf("listed %d members, want at least 2", len(names))
	}
}

// In a SOLID archive the same skip must still decode, because a successor's
// back-references reach into what this member should have written.
func TestSolidArchiveSkipStillMaintainsWindow(t *testing.T) {
	stream := solidArchiveTwoMembers(t, "one.bin", "two.bin")

	r := NewReader(volumesOf(stream))
	if _, err := r.NextEntry(); err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	// Skip the first member entirely.

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	// The solid successor must either decode correctly (window maintained) or
	// be refused (window marked incomplete). What it must NOT do is decode
	// into plausible-looking wrong content with a nil error.
	_, readErr := io.Copy(io.Discard, second)
	closeErr := second.Close()
	if readErr == nil && closeErr == nil {
		return // window was maintained; correct
	}
	if !errors.Is(closeErr, ErrSolidStreamBroken) && !errors.Is(readErr, ErrCRCMismatch) {
		t.Fatalf("solid successor after a skip: read=%v close=%v; want either "+
			"clean decode or an explicit refusal", readErr, closeErr)
	}
}
```

Add these builders, on top of `rar5Member` / `rar5Archive` from Task 8:

```go
func nonSolidArchiveWithCompressedMembers(t testing.TB) []byte {
	return rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "one.bin", content: "first member", withCRC: true}),
		rar5Member(t, memberSpec{name: "two.bin", content: "second member", withCRC: true}),
	)
}

func solidArchiveTwoMembers(t testing.TB, first, second string) []byte {
	return rar5Archive(t, true,
		rar5Member(t, memberSpec{name: first, content: "first member", withCRC: true}),
		rar5Member(t, memberSpec{name: second, content: "second member", solid: true, withCRC: true}),
	)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run "TestListingNonSolid|TestSolidArchiveSkip" ./...`
Expected: FAIL with undefined fixture builders. Write the builders, then re-run — they should then PASS against Task 8's implementation.

- [ ] **Step 3: Confirm the behaviour is real, not accidental**

Add a temporary `t.Logf` of `countingReadCloser.n` in `TestListingNonSolidArchiveDoesNotDecompress` and confirm the bytes read are approximately the archive size, not a multiple of it. Remove the log before committing.

- [ ] **Step 4: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add reader_abandon_test.go
git commit -m "$(cat <<'EOF'
test(rarengine): pin that skipping a member does not decompress it

Advancing past a member used to decode and discard its content unconditionally,
which is why listing an archive's filenames decompressed the archive. That is
only required in a solid archive, where a successor's back-references reach
into what the skipped member should have written -- and the archive header
says up front whether any exist.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Delete the old traversal

Only now, with every behaviour proven against the new types.

**Files:**
- Delete: `decompressor.go`, `engine_rar5.go`, `filereader.go`, `decompressor_test.go`, `filereader_test.go`, `engine_rar5_service_test.go`, `engine_rar5_volservice_test.go`, `decompressor_benchmark_test.go`
- Create: `errors.go`
- Modify: `splice.go` (rename `volumeSplicer`), retained crafted-archive tests

**Interfaces:**
- Consumes: everything from Tasks 4–11.
- Produces: `errors.go` holding every retained sentinel.

- [ ] **Step 1: Move the retained sentinels into errors.go**

Create `errors.go` and move, verbatim with their doc comments: `ErrNoNextVolume`, `ErrNoActiveFile`, `ErrRarBombDetected`, `ErrCRCMismatch`, `ErrWrongPassword`, `ErrPasswordRequired`, `ErrUnsupportedFormat` (from `decompressor.go`); `ErrTruncatedFile`, `ErrChecksumUnsupported`, `ErrSolidStreamBroken` (from `filereader.go`).

Do **not** move: `ErrUnexpectedVolumeBlock` (referenced nowhere — dead exported API), `ErrVolumeVersionMismatch`, `ErrRAR3EncryptionUnsupported`, `ErrRAR3UnmeasurablePayload`. Those are deleted.

Move `storeReader` and `lz50Reader` into `reader.go` — they are used by `buildChain` and are five lines each.

- [ ] **Step 2: Delete the old traversal**

```bash
git rm decompressor.go engine_rar5.go filereader.go \
       decompressor_test.go filereader_test.go \
       engine_rar5_service_test.go engine_rar5_volservice_test.go \
       decompressor_benchmark_test.go
```

`mockReadCloser` lived in `decompressor_test.go`; move it into `reader_test.go` before deleting.

- [ ] **Step 3: Re-point every test that drives `StreamDecompressor`**

Enumerate them first — the list is longer than it looks, and missing one means the package does not compile:

Run: `grep -ln "StreamDecompressor" *_test.go`

Expected (after the Task 1–3 and Step 2 deletions): `verify_password_test.go`, `decoder50_filter_test.go`, `decoder50_fixture_test.go`, `integration_download_test.go`, `crc_verify_test.go`, `packed_drain_test.go`, `decoder50_test.go`, `discard_payload_test.go`, `skip_damaged_test.go`, `encrypted_multivolume_test.go`, `integration_test.go`.

They fall into two groups, handled differently.

**Group A — mechanical translation.** `verify_password_test.go`, `decoder50_*_test.go`, `crc_verify_test.go`, `integration_test.go`, `integration_download_test.go`, `encrypted_multivolume_test.go`. These assert decoded *content*, not traversal mechanics, so the change is a rename:

| Old | New |
|---|---|
| `sd := NewStreamDecompressor(ch)` | `r := NewReader(ch)` |
| `sd.SetPassword(p)` | `r.SetPasswords([]string{p})` |
| `fh, err := sd.Next()` | `e, err := r.NextEntry()`; header is `e.Header` |
| `io.ReadAll(sd)` | `io.ReadAll(e)` |
| `sd.SetVerifyCRC(false)` | delete the call; verification is now unconditional. If a test depended on it to read a deliberately-corrupt member, assert the `ErrCRCMismatch` verdict from `e.Close()` instead. |

`integration_test.go` is the differential oracle against the system `unrar` and is the strongest evidence the rewrite decodes correctly. Translate it carefully and do not weaken an assertion to make it pass.

**Group B — replace the assertions, keep the fixtures.** `discard_payload_test.go`, `packed_drain_test.go`, `skip_damaged_test.go`. Their **fixtures are the valuable part** and each encodes a real attack; the per-site assertions are not, because they check that a particular switch case discarded, which is no longer a thing that can vary.

Keep every fixture builder. Replace the assertions with the properties from the spec, driven through `NextEntry`. The essential shape — already covered by `TestNextEntrySkipsFabricatedHeaderInPayload` in Task 8 — is that the member reached after any refusal is the archive's genuine next one, never one planted in a payload.

A test in Group B that cannot be expressed as a property of `NextEntry` is a signal, not a nuisance: it means the fixture exercises something the new design does not cover. Stop and report it rather than deleting it.

Delete `assertReachesRealEntry` and rewrite as:

```go
// assertReachesRealEntry drives the reader past skipErrors refusals and
// asserts the member it then reaches is the archive's genuine next one.
//
// Asserting only that the first call errors proves nothing -- that is equally
// true of vulnerable code. Asserting only that a payload was "consumed" is
// satisfied by consuming too much, which is what a double-discard does. The
// property is positional recovery.
func assertReachesRealEntry(t *testing.T, r *Reader, wantName string) {
	t.Helper()
	for {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("traversal ended before reaching %q: %v", wantName, err)
		}
		if e.Header != nil && e.Header.Name == wantName {
			_ = e.Close()
			return
		}
		_ = e.Close()
	}
}
```

- [ ] **Step 4: Rename volumeSplicer to match the spec**

In `splice.go` and `reader.go`, rename `volumeSplicer` to `multiVolumePayloadReader`. The name was held back only to avoid colliding with the old engine's type, which is now gone.

Run: `grep -rn "volumeSplicer" --include="*.go" .`
Expected: no output.

- [ ] **Step 5: Re-point the benchmarks**

Rewrite `decoder50_benchmark_test.go`'s reader-level benchmarks against `NewReader`/`NextEntry`. Confirm the window is still reused across `Reset`:

```go
func BenchmarkReaderResetReusesWindow(b *testing.B) {
	stream := storedArchive(b)
	r := NewReader(volumesOf(stream))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r.Reset(volumesOf(stream))
		for {
			e, err := r.NextEntry()
			if err != nil {
				break
			}
			_, _ = io.Copy(io.Discard, e)
			_ = e.Close()
		}
	}
}
```

Run: `go test -bench=BenchmarkReaderReset -benchmem -run=^$ ./...`
Expected: allocations per op in the low thousands of bytes, **not** tens of megabytes. Tens of megabytes means `Reset` is allocating a new window and the reuse invariant is broken.

- [ ] **Step 6: Run the full suite and the oracle tests**

Run: `go test -race ./...`
Expected: PASS, including `integration_test.go` against the system `unrar`. If `unrar` is absent, install it — the oracle tests are the strongest evidence the rewrite decodes correctly and must not be skipped for this task.

- [ ] **Step 7: Run the quality gate**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass, no `unused` findings.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(rarengine): delete the old traversal layer

packedCursor with its repoint/invalidate/abandoned/settled distinction,
discardPayload and dropDeclaredPayload and settle and the cause inversion,
refuse and refuseFile, markContinuable and FileError, the damaged flag and its
four writers -- all of it existed to keep two facts honest that are now
properties of values rather than of the program's history.

The per-site tests go with them. They were per-site because the invariant was
enforced per-site; the crafted-archive fixtures they were built around are
kept and re-aimed at the property that actually matters, which is that the
member reached after a refusal is the archive's genuine next one.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Rewrite CLAUDE.md and README.md

**Files:**
- Modify: `CLAUDE.md`, `README.md`
- Delete: `GEMINI.md` if it duplicates `CLAUDE.md`; otherwise update it identically.

**Interfaces:**
- Consumes: the spec's constraint inventory.
- Produces: documentation matching the code.

- [ ] **Step 1: Rewrite CLAUDE.md's Security Constraints from the inventory**

Open the spec's "Constraint inventory". For each row:
- **Structurally enforced** — one sentence naming the type that enforces it. Do not restate the old rule; a rule the compiler holds does not need prose telling a reader to hold it.
- **Carried forward** — keep the existing paragraph, with references to deleted types (`packedCursor`, `refuseFile`, `markContinuable`, `FileError`, `sd.damaged`) updated to the new ones.
- **No longer applicable** — delete.

- [ ] **Step 2: Rewrite the Architecture section**

Replace the pipeline diagram with:

```
volumes <-chan io.ReadCloser
  └─ Reader          traversal: volumes, blocks, member admission, password
       └─ volume     one volume's bytes and the position within them
       └─ Entry      one member: reader chain, byte budget, CRC, verdict
            └─ decoder50 / storeReader
                 └─ cbcDecryptReader (if encrypted)
                      └─ multiVolumePayloadReader
```

Update the key-files table: remove `decoder30.go`, `engine_rar3.go`, `unpack.go`, `decompressor.go`, `engine_rar5.go`, `filereader.go`; add `volume.go`, `reader.go`, `entry.go`, `splice.go`, `crypto.go`.

- [ ] **Step 3: Rewrite README.md**

- Remove the `UnpackDir` section entirely.
- Rewrite the streaming example against `NewReader`/`NextEntry`/`Entry`:

```go
r := rarengine.NewReader(volumes)
r.SetPasswords([]string{"first-guess", "second-guess"})

for {
	e, err := r.NextEntry()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, rarengine.ErrNoNextVolume) {
			break
		}
		return err // the archive stopped being parseable
	}
	if e.Header.IsDir {
		_ = e.Close()
		continue
	}
	if _, err := io.Copy(dst, e); err != nil {
		log.Printf("skipping %s: %v", e.Header.Name, err)
	}
	// Close reports the member's verdict. A member that failed does not end
	// the archive: call NextEntry again.
	if err := e.Close(); err != nil {
		log.Printf("%s: %v", e.Header.Name, err)
	}
}
```

- State that RAR3 archives are not decoded, and that `ReadRAR3BlockHeader` / `ParseRAR3FileHeader` remain for inspection.
- Re-run the benchmarks and replace the stale numbers with real output from `go test -bench=. -benchmem`.

- [ ] **Step 4: Verify the docs against the code**

Run: `grep -n "StreamDecompressor\|UnpackDir\|SetVerifyCRC\|SetPassword\b\|FileError\|packedCursor\|refuseFile" CLAUDE.md README.md`
Expected: no output. Any hit is documentation describing code that no longer exists.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md GEMINI.md
git commit -m "$(cat <<'EOF'
docs(rarengine): rewrite the guidance against the new invariants

Most of the security constraints were prose keeping a per-site obligation
honest. Where a type now holds the invariant, the paragraph is replaced by one
sentence naming that type: a rule the compiler enforces does not need prose
telling a reader to enforce it.

What remains is what is still genuinely a runtime guard.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Open PR 2

**Files:** none.

- [ ] **Step 1: Run the full gate one last time**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
Expected: all pass.

- [ ] **Step 2: Confirm the endpoint**

Run: `ls *.go | grep -v _test | xargs wc -l | tail -1`
Expected: approximately 3,000 lines, down from 5,670. A number well above that means something was kept that the spec deletes; well below means something was dropped that it keeps — check against the spec's Files table either way.

- [ ] **Step 3: Verify the exported surface matches the spec**

Run: `go doc -all . | grep "^func \|^type " | sort`

Compare against the spec's "Exported surface" section. Confirm present: `Reader`, `NewReader`, `Reset`, `SetPasswords`, `NextEntry`, `Entry`, `ReadBlockHeader`, `ParseArchiveHeader`, `ParseFileHeader`, `ParseCryptHeader`, `ReadRAR3BlockHeader`, `ParseRAR3FileHeader`, `VerifyPassword`, `VerifyFilePassword`. Confirm absent: `StreamDecompressor`, `FileError`, `UnpackDir`, `SetVerifyCRC`, `Version`, `ArchiveVersion`.

- [ ] **Step 4: Run the review gate**

Run the `pr-review-toolkit:review-pr` workflow on the local diff, then `quality-lenses` in `diff` mode, and triage what they return. This repository's defects have historically been found by review rather than by tests — four security defects pre-merge, including one on a pure refactor.

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin HEAD
gh pr create --title "refactor(rarengine): rewrite the traversal layer" --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-08-21-rarengine-simplification-design.md.

Stream position and per-member verdict become properties of values rather than
facts about the program's history:

- `volume` owns one volume's bytes and position; `next()` skips the current
  block's remaining payload before reading the following header, so a header
  cannot be parsed out of a previous block's payload.
- `Entry` owns one member's verdict, delivered by both `Read` and `Close`.
  Refusals are terminal entries, so `NextEntry`'s errors are archive-level only.
- `Window` owns the solid-history damage flag, with `BeginFile` as the single
  entrance.

Also fixes a live defect: RAR5's continuation path never got the per-volume
encryption re-check that PR #44 added for RAR3, so a member whose continuation
claimed encryption had that volume's ciphertext delivered verbatim as content
with `Encrypted` reported false.

Deletes `packedCursor`, `discardPayload`/`dropDeclaredPayload`/`settle`,
`refuse`/`refuseFile`, `markContinuable`/`FileError`, `sd.damaged`,
`errorReader`, and `StreamDecompressor`.

**Review focus:** the load-bearing claim is that `volume.next()` skipping
before reading makes the positioning bug class unreachable. If that is wrong,
most of the constraint inventory's "structurally enforced" column collapses
back into guards.
EOF
)"
```

- [ ] **Step 6: Report to the user**

Do not merge. Report the PR URL, the final line count, and anything the review gate surfaced that was not fixed.
