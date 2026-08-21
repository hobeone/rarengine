# rarengine simplification — target design

Status: approved design, 2026-08-21. Describes the end state, not the route to it.
The commit sequence belongs in the implementation plan.

## Why

The library is 5,670 lines of non-test code. The RAR decoding itself — Huffman,
LZ77, bit reader, window, filters, vint, header parsing — is ~1,600 of those and
has produced almost none of the last twenty pull requests.

Nearly all accumulated complexity is *stream-positioning discipline*: machinery
that exists to answer "where is the stream right now?" and to keep that answer
honest across two engines.

| Mechanism | Lines | Exists because |
|---|---|---|
| `packedCursor` (`abandoned`/`settled`/`invalidate`/`repoint`/`drain`) | ~90 | a count can go stale across volumes |
| `discardPayload` / `dropDeclaredPayload` / `settle` / the `cause` inversion | ~60 per engine | a `switch` case might forget to drop payload |
| `refuse` / `refuseFile` / `markContinuable` | ~70 | a `FileError` must *prove* the stream is positioned |
| `sd.damaged` (four writers) | ~40 | a refused file leaves a hole inside the window bound |
| `rar3Engine.fatal` | ~20 | one refusal cannot discard, so traversal must latch |

Every recurring defect has had one shape: **a block header was parsed out of bytes
that were really a previous block's payload.** Each fix added a guard at a site.
The invariant is global; it was enforced locally in about fourteen places across
two engines, and roughly seventy percent of `CLAUDE.md` is prose keeping those
places honest. Prose is not enforcement.

Two facts were both encoded as *the timing of a return value from `Next()`*:
whether the stream sits on a block boundary, and whether the previous member
failed. Neither is a fact about any value, so neither could be checked. This
design attaches each to a value that owns it.

## The consumer

gonzbd is the only consumer, and what it actually uses was surveyed rather than
assumed. It uses rarengine two ways:

- **Decode** — `NewStreamDecompressor` + `Next`/`Read`, in
  `internal/unpack/go_unrar.go` and `internal/directunpack/directunpack.go`.
- **Inspect** — the raw header API in `internal/rarheader/rarheader.go`:
  `ReadBlockHeader`, `ParseFileHeader`, `ParseArchiveHeader`,
  `ParseCryptHeader`, the `HeaderType*` constants, `VerifyPassword`,
  `VerifyFilePassword`, `ErrBadHeaderCRC`, and — for RAR3 — 
  `ReadRAR3BlockHeader` and `ParseRAR3FileHeader`.

It uses **no part of `UnpackDir`**: not `UnpackOptions`, `UnpackResult`,
`DamagedEntry` or `SortVolumes`. It reimplements extraction policy itself,
including its own path sanitizer (`internal/unpack/sanitized_path.go`).

Both usages shape the scope below.

## Scope decisions

- **RAR3 decoding is dropped; RAR3 header parsing is kept.** `decoder30.go` and
  `engine_rar3.go` go. `header_rar3.go` stays: `InspectRar3` uses it, and its
  own comment records that it deliberately avoids the RAR3 engine because that
  engine only implements the store method. Every RAR3 security constraint being
  retired is engine-side, not parser-side.
- **`UnpackDir` is deleted**, with `UnpackOptions`, `UnpackResult`,
  `DamagedEntry`, `SortVolumes`, `ErrUnusableName`, `uniquePath` and the
  `os.Root` sandbox. It has no caller and duplicates logic gonzbd already owns.
  rarengine becomes a decode-and-inspect library that never touches the
  filesystem.

  `sanitizePath` is **not** part of this and stays. It is applied in the
  parsers (`header.go:549`, `header_rar3.go:219`) to every `fh.Name` as the
  header is decoded, not at a write site, so deleting `UnpackDir` strands
  nothing and removing it would change what `FileHeader.Name` contains for
  every consumer.
- **Verification is unconditional.** `SetVerifyCRC` is deleted along with the
  `accumulate` branch.
- **Passwords are a list**, resolved inside the reader. See below.
- **Kept**: solid archives, RAR5 per-file encryption, archive-level header
  encryption, multi-volume streaming.
- **No backwards compatibility.** `StreamDecompressor` is deleted outright; the
  gonzbd integration is reimplemented against the new API.
- **Zero-allocation applies to the 32 MB window and `Reset` reuse only.**
  Per-file objects are ordinary allocations, amortised over megabytes of
  payload. The per-file reuse that exists today is the direct cause of the
  stale-count bug class.

## The end state

### Two surfaces

rarengine exposes two deliberately separate things:

- **decode** — `Reader` / `Entry`. Position is owned by the library; no caller
  can read a header off the stream it is traversing.
- **inspect** — `ReadBlockHeader`, the `Parse*` functions, `Verify*`. Raw,
  read-only, and **the caller owns position**. Documented as such.

`Reader` uses the inspect functions internally but never admits a caller into
its own stream. The two do not interact, which is why exporting the second does
not weaken the first.

### Layers

```
volumes <-chan io.ReadCloser
  └─ Reader          traversal: volumes, blocks, member admission, password
       └─ volume     one volume's bytes and the position within them
       └─ Entry      one member: reader chain, byte budget, CRC, verdict
            └─ decoder50 / storeReader
                 └─ cbcDecryptReader (if encrypted)
                      └─ multiVolumePayloadReader (splices volume.payload() across volumes)
```

`Reader` and `Entry` replace `StreamDecompressor`, `versionedEngine`,
`rar5Engine` and `fileReader`. Multi-volume splicing is handled directly by
`Entry` coordinating with `Reader`.

### `volume` — position becomes a value

```go
// volume owns one RAR volume's byte stream and the position within it.
//
// It is the only way the traversal obtains a block header, and next()
// re-establishes the block boundary itself before reading one. A header
// therefore cannot be parsed out of a previous block's payload -- not because
// every caller remembers to discard, but because no caller is offered the
// chance to skip.
type volume struct {
	rc   io.ReadCloser
	body io.LimitedReader // what remains of the current block's declared payload
}

// openVolume reads and validates the RAR5 signature, leaving v on the first
// block boundary. A RAR3 signature is reported as ErrUnsupportedFormat.
func openVolume(rc io.ReadCloser) (*volume, error)

// useEncryptedHeaders switches next() to the decrypting header path, once an
// encryption header has yielded a key.
func (v *volume) useEncryptedHeaders(key []byte)

// next skips whatever remains of the current block's payload, then reads the
// following header. io.EOF means this volume is exhausted.
func (v *volume) next() (*BlockHeader, error) {
	if _, err := io.Copy(io.Discard, &v.body); err != nil {
		return nil, err
	}
	h, err := ReadBlockHeader(v.rc)
	if err != nil {
		return nil, err
	}
	v.body = io.LimitedReader{R: v.rc, N: h.DataSize}
	return h, nil
}

// payload is the current block's declared bytes, bounded by DataSize.
func (v *volume) payload() io.Reader { return &v.body }
```

Three properties do the work:

1. **The skip is at the front of the only entrance.** A `finish()`-style call
   after the fact would be exactly as forgettable as today's discard. Putting it
   before the read means the obligation is discharged by asking for the thing you
   wanted anyway.
2. **The bound is the same number the file consumes.** `header.go` sets a RAR5
   file header's `PackedSize` from the block's `DataSize`. There is one count, so
   no second count can disagree with the first. (This was never true in RAR3,
   which is what made `lhdLarge` dangerous; it leaves with the RAR3 engine.)
3. **A volume advance constructs a new `volume`.** It does not repoint an old
   one. A count outliving its volume is not a rule to follow but a lifetime that
   cannot occur, and the previous volume becomes unreachable rather than merely
   closed.

`volume.next()` is the **only** thing that moves the traversal's stream. `Entry`
does no draining, because draining is also required where no `Entry` exists at
all: service records, unknown block types, archive headers, unparsable file
headers, refused members. One mechanism for one invariant.

Archive-level header encryption lives here rather than in `Reader`, because
"how a header is read" is the volume's business and the choice must not be
expressible at a call site. `Reader` parses the encryption header, resolves the
password, and calls `useEncryptedHeaders`. As today, the key does not carry
across a volume boundary — encrypted headers on multi-volume archives remain
unsupported, and are reported rather than silently misparsed.

### `Reader`

```go
type Reader struct {
	volumes  <-chan io.ReadCloser
	vol      *volume // nil = none open; every failure path leaves it nil
	win      *Window
	entry    *Entry
	passwords []string
	resolved  string // latched once a candidate verifies
	solid     bool   // from the archive header; see Close below
}

func NewReader(volumes <-chan io.ReadCloser) *Reader
func (r *Reader) Reset(volumes <-chan io.ReadCloser)
func (r *Reader) SetPasswords(candidates []string)

// NextEntry finishes any active entry, scans forward, and returns the next
// member. io.EOF reports that the archive is over.
//
// Its errors are archive-level only: a malformed block header, no next
// volume, an unsupported format, end of stream. Every per-member outcome is
// delivered by the Entry.
func (r *Reader) NextEntry() (*Entry, error)
```

`Reset` keeps the 32 MB window; nothing else survives it.

### Passwords

`SetPasswords([]string)` replaces `SetPassword(string)`. The reader resolves a
candidate at the first encrypted thing it meets — the `CryptHeader` of a
header-encrypted archive, or the first encrypted file header's `EncCheck` —
using the existing check-value fold, which requires no decryption and no
decompression. The winner is latched for the archive, so the cost is one key
derivation per candidate per archive rather than per member.

This deletes `errorReader` (four uses in `engine_rar5.go`), whose only purpose
is smuggling a deferred password or KDF failure into the read path. With the
password resolved at admission, those become terminal `Entry` values like every
other refusal.

`VerifyPassword` and `VerifyFilePassword` stay exported — they are part of the
inspect surface and gonzbd's `rarheader` uses them directly.

Limitation, to be documented rather than engineered around: an archive carrying
no check value cannot have a candidate verified cheaply. The reader uses the
first candidate and the failure surfaces as `ErrCRCMismatch`. Automatically
re-running the archive per candidate is explicitly out of scope — it means
re-reading every volume, and modern RAR stores a check value by default.

### `Entry`

```go
// Entry is one member of the archive.
type Entry struct {
	// Header is the FIRST block's header and does not change for the life of
	// the entry.
	Header *FileHeader

	cur *FileHeader // header in force: LastBlock, UseMac, the whole-file CRC32
	// src, size, remaining, crc, done
}

func (e *Entry) Read(p []byte) (int, error)
func (e *Entry) Close() error
```

- **The verdict lives on the entry it describes**, delivered by both `Read` (at
  the end of the stream) and `Close` (for a caller that skips). Both return the
  same recorded `done`, so a member never completes silently whichever way the
  caller drives it, and the verdict is never single-channel. `errcheck` is
  enabled here with no exclusion presets and flags an unchecked `Close`,
  deferred or not — verified against this repository's `.golangci.yml`.
- **`Entry.Header` is stable.** The header in force moves to unexported `cur`.
  For a multi-volume member the whole-file CRC32 and `UseMac` live in the last
  part's header, which is why `cur` exists; the caller keeps the header it asked
  for. This retires a documented wart: `FileError.Header` is currently "the LAST
  part's, not the one `Next` originally returned."
- **A refused member is still an `Entry`**, already terminal: a rar bomb, a
  broken solid run, an unparsable file header, an unresolvable password. `Read`
  and `Close` return the cause. This is what makes `NextEntry`'s archive-only
  error set literally true rather than true-with-exceptions.

#### Abandoning an entry is cheap in a non-solid archive

`Close` on a partly-read entry must decode the remainder only to keep the LZ77
window valid for a *solid* successor. `ArchiveHeader.Solid` states up front
whether the archive has any. So:

- **non-solid archive** — `Close` decodes nothing. `volume.next()` skips the raw
  packed bytes on the way to the following header.
- **solid archive** — `Close` decodes the remainder into the window, as today.

Today `endFile` always decodes-and-discards, which is why gonzbd's
`InspectRar5` decompresses an entire archive to list its filenames while
`InspectRar3` deliberately does not. This makes the fast path the default
without an API change.

#### Multi-volume coordination & payload splicing

When a file's payload spans multiple volumes:
1. `Entry` reads from a `multiVolumePayloadReader` that wraps `volume.payload()`.
2. When the inner `v.payload()` reports `io.EOF`:
   - If `e.cur.LastBlock == true`, the member is finished; return `io.EOF`.
   - If `e.cur.LastBlock == false`, request the next volume payload from `Reader`.
3. `Reader.nextVolumePayload()`:
   - Fetches the next `io.ReadCloser` from `volumes` and constructs a fresh `volume`.
   - Loops on `v.next()` until finding `HeaderTypeFile` (skipping `HeaderTypeArchive` automatically via `v.next()`'s discard mechanism).
   - Validates that the continuation's encryption state matches the member's initial state: `if fh.Encrypted != e.Header.Encrypted { return nil, ErrCorruptFileHeader }`.
   - Updates `e.cur = fh` (capturing the whole-file CRC32, `LastBlock`, and `UseMac`).
   - Returns `v.payload()`.

#### Abandoned multi-volume members guard

If a consumer stops reading an entry mid-file and calls `NextEntry()` while the entry still has continuation parts on subsequent volumes:
- `v.next()` on the current volume exhausts to `io.EOF`.
- `NextEntry()` advances volumes and encounters continuation headers (`!fh.FirstBlock`).
- `NextEntry()` must loop and discard any header where `!fh.FirstBlock`. Because `v.next()` bounds and drains each continuation block's payload automatically, this cleanly drains all trailing parts until the next entry (`fh.FirstBlock == true`) is reached.

#### Solid archive incomplete state guard

In a solid archive, skipping an entry without decompressing it corrupts the LZ77 history for subsequent solid members. If `Entry.Close()` or `NextEntry()` finishes an entry that did not decode to `UnpackedSize`, it **must** invoke `Window.MarkIncomplete()`. Any subsequent solid member calling `Window.BeginFile(true)` will then fail immediately with `ErrSolidStreamBroken`.

### Exported surface

```
decode   Reader  NewReader Reset SetPasswords NextEntry
         Entry   Header Read Close
inspect  ReadBlockHeader ParseArchiveHeader ParseFileHeader ParseCryptHeader
         ReadRAR3BlockHeader ParseRAR3FileHeader
         VerifyPassword VerifyFilePassword
         BlockHeader ArchiveHeader FileHeader CryptHeader ExtraRecord
         FileHeader.Mode, the HeaderType* and flag constants
```

Sentinels kept: `ErrNoNextVolume`, `ErrNoActiveFile`, `ErrRarBombDetected`,
`ErrCRCMismatch`, `ErrWrongPassword`, `ErrPasswordRequired`, `ErrTruncatedFile`,
`ErrChecksumUnsupported`, `ErrSolidStreamBroken`, `ErrBadHeaderCRC`,
`ErrBadBlockHeader`, `ErrCorruptBlockHeader`.

Deleted: `StreamDecompressor`, `FileError`, `ArchiveVersion`, `Version`,
`SetPassword`, `SetVerifyCRC`, `UnpackDir`, `UnpackOptions`, `UnpackResult`,
`DamagedEntry`, `SortVolumes`, `ErrUnusableName`, `ErrVolumeVersionMismatch`,
`ErrRAR3EncryptionUnsupported`, `ErrRAR3UnmeasurablePayload`,
`ErrUnexpectedVolumeBlock` — the last of which is declared in
`decompressor.go:17` and referenced nowhere, so it is already dead exported API.

Added: `ErrUnsupportedFormat`, `SetPasswords`.

### Version detection

With one decodable format left, `ArchiveVersion`, `Version()` and
`ErrVolumeVersionMismatch` are deleted. `openVolume` either recognises a RAR5
signature or returns `ErrUnsupportedFormat`, which subsumes the mismatch case:
a later volume that is not RAR5 fails to open at all, and the engine-selection
switch it guarded no longer exists.

### `Window` owns damage

```go
// BeginFile prepares the window for a member. ErrSolidStreamBroken if the
// member is solid and the history is not what its back-references assume.
func (w *Window) BeginFile(solid bool) error

// MarkIncomplete records that this member left the history in a state a solid
// successor's back-references do not assume.
func (w *Window) MarkIncomplete()
```

`sd.damaged` — four writers, and a comment warning that a fifth would have to
answer the same question — becomes state on the thing it describes. One owner,
one entrance, and the `error` return makes handling the refusal compulsory
rather than customary.

## Defect to fix as part of this work

**The RAR5 continuation-encryption gap.** PR #44 fixed this for RAR3 and
`CLAUDE.md` documents it — *"A per-file header flag must be re-checked on every
volume advance, not only at admission"* — but it was never applied to RAR5.

`engine_rar5.go`'s `processVolumePayloadHeader` handles a continuation block with
`ParseFileHeader` → `advanceVolume(fh)` → `repoint`, with no encryption check,
while `newDecompressionReader` derives the key from the *first* block's
`fh.Encrypted` and installs the CBC reader once for the whole spliced stream.

A member whose first block declares plaintext and whose continuation declares
encryption therefore has that volume's ciphertext spliced in and delivered
verbatim as content, with `Encrypted` reported false. The inverse decrypts bytes
that were never ciphertext.

Severity is integrity, not disclosure: the archive already controls the bytes and
the CRC32, so nothing is leaked that it did not have. What it buys is the ability
to make this library report `Encrypted: false` over content it did not decrypt.

The new design checks this explicitly in `Reader.nextVolumePayload`:
`if fh.Encrypted != e.Header.Encrypted { return nil, ErrCorruptFileHeader }`.
Pinned with a unit test.

## Constraint inventory

Every security constraint in the current `CLAUDE.md`, and what happens to it.
Read top to bottom this is the acceptance criteria for the work, and the
skeleton of the replacement `CLAUDE.md`.

### Structurally enforced — prose collapses to one sentence

| Constraint | Enforced by |
|---|---|
| Never let a block header be parsed out of a previous file's payload | `volume.next()` skips before reading. The traversal has no other way to read a header. |
| No block's declared payload survives into the next header read; accounting by default rather than by obligation | Same. The default/obligation inversion, the `cause` accumulator and the three documented return reasons all disappear with the per-case discard. |
| Refusing a file means dropping its payload, whatever the reason for the refusal | Same. The skip is unconditional and knows nothing about why a block was not claimed. |
| The packed remainder is tracked per volume, never captured once, never read from a closed volume | `volume.body` is a field of the volume; an advance constructs a new one. A stale count is unrepresentable. |
| Trailing continuation blocks of an abandoned multi-volume file are cleanly drained | `NextEntry()` loops and discards headers where `!fh.FirstBlock`. `volume.next()` automatically drains their bodies. |
| A file's terminal error is durable for that file | `Entry.done`, set once, returned by both `Read` and `Close`. |

### Carried forward — still a runtime guard, still needs a test

| Constraint | Notes |
|---|---|
| `sanitizePath` is mandatory for all archive-internal filenames | Unchanged, and applied in the parsers rather than at a write site, so every `FileHeader.Name` rarengine emits is already safe. Deliberate defence in depth: it protects a consumer that writes `fh.Name` directly, at the cost of destroying the evidence that an archive attempted traversal. The consumer that calls `Create` still owns the authoritative check — a library that writes no files cannot commit a traversal — and gonzbd has `internal/unpack/sanitized_path.go` for that. |
| The rar-bomb guard (`UnpackedSize > 1000 * PackedSize` for files > 1 MB) | Now expressed as a terminal `Entry` rather than a `refuse` call. |
| The window history bound in `CopyBytes` (`distance > w.historyLen()`) | Untouched. Still what makes the skipped memclr a performance choice rather than an information leak. |
| AES key material must never appear in error messages or log output | Discipline, not structure. Carried as prose, scoped to `crypto.go`. |
| A file must never terminate cleanly without meeting `UnpackedSize` or reporting why; `ErrTruncatedFile` must not satisfy `errors.Is(err, io.EOF)` | Now decided in `Entry`. The sentinel rule is unchanged and load-bearing. |
| A header flag must never switch verification off; gate on the produced size, not on what the archive says about itself; `UseMac` fails with `ErrChecksumUnsupported` | Strengthened: with `SetVerifyCRC` deleted, nothing can turn verification off at all. |
| Sizes are validated where they are decoded; negative sizes rejected; `remaining <= 0` as the backstop | Both halves survive. RAR5: a size vint carries 70 bits and can set the sign bit of an `int64`. RAR3: `ParseRAR3FileHeader` is kept and still composes a size from two attacker-chosen halves, and gonzbd's `InspectRar3` relies on the rejection. |
| Damage is recorded from what happened to the file, never from the error the caller receives | Survives as a rule, but with one writer: `Entry.Close` calls `Window.MarkIncomplete` from the outcome it observed. |
| A per-file header flag must be re-checked on every volume advance | **Newly applies to RAR5** — `Reader.nextVolumePayload` asserts `fh.Encrypted == e.Header.Encrypted`, returning `ErrCorruptFileHeader` on mismatch. The `refuseFile`-versus-`refuse` distinction this constraint documents disappears with both functions. |
| A flag's name is not evidence of its value (`LHD_SALT` vs `LHD_PASSWORD`) | Retained. `header_rar3.go` survives, so the named constants and the two-bit encryption test survive with it. |

### No longer applicable

| Constraint | Why |
|---|---|
| A `FileError` is a promise that the stream is standing on the next block header, and only a completed drain may make it | `FileError` and `markContinuable` are deleted. The verdict travels on the `Entry`, so no error needs to carry a positioning claim. |
| The terminator exemption rests on `nextVolume` clearing `sd.currentVol` | There is no exemption: the skip is unconditional, and an advance replaces the volume rather than repointing it. |
| A declared size of zero is not evidence that a block declares nothing | RAR3 engine only. A RAR5 `DataSize` measures the whole payload. |
| A refusal that cannot discard must end traversal | RAR3 engine only (`ErrRAR3UnmeasurablePayload`). Every RAR5 block is measurable. |
| A RAR3 subblock declaring `lhdLarge` is refused, not discarded by declared length | RAR3 engine only. The parser never skipped payload; only the engine did. |
| `ErrUnusableName` reports a member whose name sanitizes to nothing | Only something choosing a destination path can ask that question, and nothing in rarengine chooses one any more. Leaves with `UnpackDir`. |

## Files

| Disposition | Files |
|---|---|
| Untouched | `huffman.go` `bit_reader.go` `vint.go` `decoder50.go` `filters.go` `filter_*.{go,s}` `header_crypt.go` `verify_password.go` `header_rar3.go` |
| Amended | `window.go` (gains `BeginFile` / `MarkIncomplete`), `header.go` (loses the RAR3 engine hooks) |
| Deleted | `decoder30.go` `engine_rar3.go` (RAR3 decoding); `unpack.go` (no consumer); `decompressor.go` `engine_rar5.go` `filereader.go` (traversal) |
| Written fresh | `volume.go` `reader.go` `entry.go` `crypto.go` |

The traversal layer is written from scratch rather than adapted: its failure mode
is keeping a field because something must have needed it. The decode core and the
header parsers are left strictly alone in the same directory, so `git blame`
survives on every line worth keeping and nothing is copied.

`crypto.go` is the one deliberate lift: `pbkdf2HmacSha256`, `verifyEncCheck` and
`cbcDecryptReader` move verbatim out of `decompressor.go`. They are pure, correct
and expensively learned — `cbcDecryptReader`'s held-back sub-block tail cost a
multi-volume defect to discover.

## Tests

Kept, re-aimed at the new API:

- `integration_test.go` — differential oracle against the system `unrar`. The
  strongest evidence the library has and unaffected by the restructuring.
- `FuzzHuffman`, `decoder50_*_test.go`, `window_test.go`, `bit_reader_test.go`,
  `huffman_test.go`, `vint_test.go`, `filters_test.go` — decode core, untouched.
- Every crafted-archive fixture from `discard_payload_test.go`,
  `packed_drain_test.go` and `skip_damaged_test.go`. The fixtures are the
  valuable part and each one encodes a real attack.
- `encrypted_multivolume_test.go`, `crc_verify_test.go`, `header_time_test.go`,
  `verify_password_test.go`, `header_test.go`.

Replaced rather than ported: the per-site assertions in those crafted-archive
files — of order 2,300 lines — which check that a particular `switch` case
discarded, that a particular refusal drained, that a particular error proved
`settled()`. They are per-site because the invariant was enforced per-site.
Under `volume.next()` there is one site, and they become a small set of
properties over it, driven by the retained fixtures through the public API:

- after any block, whatever its type and whoever did or did not claim it, the
  next header is read at the block boundary;
- a member's payload cannot exceed its block's declared size;
- a fabricated header planted in a block's payload is never returned by
  `NextEntry`;
- an entry always reports a verdict, by `Read` or by `Close`;
- a solid member after damage is refused;
- a continuation whose encryption claim differs from its entry's is refused.

Deleted outright: `decompressor_rar3_test.go` (RAR3 engine),
`unpack_test.go`, `unpack_damaged_test.go`, `unpack_refusal_test.go`,
`unpack_realarchive_test.go` (`UnpackDir`) — 1,786 lines.

## Expected endpoint

| | Lines |
|---|---|
| Non-test code today | 5,670 |
| RAR3 decoding + `unpack.go` deleted | −1,710 |
| Traversal layer deleted | −1,609 |
| `volume.go` + `reader.go` + `entry.go` + `crypto.go` written | +~650 |
| **Endpoint** | **~3,000** |

One traversal, one format decoded, no filesystem. `CLAUDE.md` from 18 KB to
roughly 5 KB, because most of it becomes "the scanner guarantees this."

## Follow-on work in gonzbd, out of scope here

- Reimplement the decode integration against `Reader`/`Entry`.
- Replace the per-password re-run of the whole archive with `SetPasswords`.
- Point `InspectRar5` at the inspect surface, or rely on the cheap-abandon
  behaviour above, so listing filenames stops decompressing the archive.

## Open questions

None. Scope, alloc budget, facade removal, password handling, `UnpackDir`,
verification and test disposition are all settled above.
