# Plan: issue #62 — file headers carry what their archive encoded, and never a mix of two records

**Goal:** every `*FileHeader` that `parseFileHeader` returns alongside an error carries every
field from the FIRST extra record of each type that the archive encoded correctly; `Encrypted`
reflects whether the member carries an encryption record at all; and no header — erroring or not
— is built from two records of the same type. The first record of a type is authoritative even
when it fails to parse: a later record of that type is a duplicate, not a replacement. For an
archive that repeats none of the parsed record types (1–3), no caller receives a different error
than today. A header that repeats one of them is refused with `ErrCorruptFileHeader`, unless its
size is refused first or an earlier record, of any type, already failed — then that error stands.
Repeated records of any other type are ignored, as today.

**Direction (settled at Gate 1, see issue #62):** parse every extra record, before the size checks
and past any failing record; set `Encrypted` from the encryption record's presence; report errors
in today's priority; refuse a second record of any known type. All production changes in
`header.go`. No exported name or signature changes, so a patch-level fix.

**Repo:** `/home/hobe/software/rarengine/.claude/worktrees/fix+62-header-before-extra-records`,
branch `worktree-fix+62-header-before-extra-records`, based on `aa35188`.

## Global constraints

- Quality gate before every commit, run AFTER staging:
  `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
- Conventional Commits, scope `rarengine`. Trailers:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01EPsn1CyA9wstZZd5UPHM6p`.
- Write no code comment that mentions this plan, a task number, or a step.
- Well-formed RAR5 framing comes from `testbuild_test.go` only (repo CLAUDE.md, *Integration
  Testing*). A fixture's malformation may be written at its call site; valid framing may not.
- `buildRAR5Member` must not quietly rewrite what a fixture declared.
- Every new test is mutation-checked: revert the task's production change and confirm THAT test
  goes red, before committing.
- The security constraints in repo CLAUDE.md stay intact — `sanitizePath` still runs on every name;
  nothing here touches the rar-bomb guard, `CopyBytes`, or key material.
- No repo docs, code comments, issue text or PR text name any downstream consumer of this library.

## Invariant this plan must preserve

**A header whose encryption parameters did not fully parse only ever accompanies a non-nil error.**
The production readers of those fields — `Encrypted` at `reader.go:782` (`buildChain`),
`inspect.go:81` (`VerifyPassword`) and `splice.go:213` (`nextVolumePayload`); `Salt`, `IV`,
`KdfCount` and `EncCheck` at `reader.go:706,788-797` and `verify_password.go:89`; `UseMac` at
`entry.go:351,388-392` — are each reached only after `parseFileHeader` returned a nil error. Task 2
makes `Encrypted` true before the record's parameters are known, so this invariant is what keeps
`buildChain` from deriving a key from a nil salt. It holds because a failing record makes
`parseExtraRecords` return an error (Task 1 returns the first, never swallows one), which makes
`parseFileHeader` return an error. A plan-review probe confirmed it with all tasks applied: every
header returned with a nil error is identical to HEAD's, and across 5,016 record sequences that
repeat no type 1–3 every error is identical to HEAD's. A repeated type 1–3 changes errors by design
(Task 4): wherever no size refusal and no earlier record failure outranks it, the duplicate's
`ErrCorruptFileHeader` replaces whatever HEAD reported — nil for two valid records, or the
sentinel of any LATER failing record, of the same type or another (for example
`[hash, hash, enc version 99]` went from `ErrUnknownEncryptMethod` to the duplicate error). Where
HEAD already said `ErrCorruptFileHeader`, only the message text changes. No `testdata/*.rar`
archive carries a duplicate — the probe walked 101 archives and 132 extra areas.

---

## Task 1 — one ordered extra-record list, parsed in full

**Files:**
- Modify: `header.go` — `parseExtraRecords`
- Modify: `testbuild_test.go` — replace `memberSpec.encRecord` with an ordered `extraRecords`
  field; add `encryptionRecordBody`
- Modify: `inspect_test.go` — `encryptedMemberHeader` uses the new field and helper
- Modify: `splice_test.go:355` — `encRecord: encodeVint(99)` becomes an `extraRecords` entry
- Test: `header_test.go`

**Why:** parsing stops at the first failing record, so a malformed hash or time record placed
before a valid encryption record hides it entirely. `parseBlockHeaderFields` (`header.go:265-288`)
already cuts each record to its own declared length and fails the whole block header on broken
size or type framing, so one record's bad body cannot desynchronise the next.

The fixture side replaces rather than adds. `encRecord` emits exactly one record with its type
hard-coded to 1, through a block that would be duplicated statement for statement by any second
mechanism. A single ordered list expresses every fixture `encRecord` can, plus the record ORDER
these tests need, with one framing path. `encRecord` has two call sites (`inspect_test.go:361`,
`splice_test.go:355`), both rewritten here.

**Builder:**

```go
// extraRecordSpec is one extra-area record, emitted as its type vint followed
// by Body verbatim.
type extraRecordSpec struct {
	Type uint64
	Body []byte
}
```

`memberSpec`'s `encRecord` field and its comment are replaced by:

```go
	// extraRecords is the header's extra area, emitted record by record in the
	// order given. Each Body is written verbatim after its type, so a fixture
	// states a malformed record directly: an unsupported encryption version is
	// {Type: 1, Body: encodeVint(99)}. Order is part of what a fixture can say,
	// because extra records are parsed in archive order.
	extraRecords []extraRecordSpec
```

and the `if s.encRecord != nil { ... }` block in `buildRAR5Member` is replaced by:

```go
	for _, r := range s.extraRecords {
		var rec bytes.Buffer
		rec.Write(encodeVint(r.Type))
		rec.Write(r.Body)
		extra.Write(encodeVint(uint64(rec.Len())))
		extra.Write(rec.Bytes())
		blockFlags |= headerFlagHasExtra
	}
```

`encryptionRecordBody` is hoisted out of `inspect_test.go`'s `encryptedMemberHeader`, generalised
only as far as the tests below need:

```go
// encryptionRecordBody is a well-formed RAR5 file-encryption record body
// (everything after the record-type vint): AES-256, KDF count 15, a salt of
// sixteen copies of salt, a fixed IV, and the flags given. fileEncCheckPresent
// appends a 12-byte password check value; fileEncUseMac is recorded as given.
func encryptionRecordBody(flags uint64, salt byte) []byte {
	var enc bytes.Buffer
	enc.Write(encodeVint(0)) // encryption version 0 (AES-256)
	enc.Write(encodeVint(flags))
	enc.WriteByte(15)                         // kdf count
	enc.Write(bytes.Repeat([]byte{salt}, 16)) // salt
	enc.Write(bytes.Repeat([]byte{0xBB}, 16)) // IV
	if flags&fileEncCheckPresent != 0 {
		enc.Write(bytes.Repeat([]byte{0xCC}, 12)) // check value
	}
	return enc.Bytes()
}
```

`encryptedMemberHeader(t, name, withCheck)` keeps its signature and builds its body as
`encryptionRecordBody(flags, 0xAA)`, where `flags` is `fileEncCheckPresent` when `withCheck` and 0
otherwise — byte-identical to today's output. `splice_test.go:355` becomes
`extraRecords: []extraRecordSpec{{Type: 1, Body: encodeVint(99)}}`.

- [ ] **Step 1: refactor the builder alone and prove it changes no bytes.** Before touching
  `header.go`, apply the builder change and both call-site rewrites, then run the full suite. It
  must be green: a fixture rewrite that alters output would show up here, not later.
- [ ] **Step 2: failing test.** `TestExtraRecordFailureDoesNotHideALaterEncryptionRecord` in
  `header_test.go`: a member whose `extraRecords` are
  `[{Type: 3, Body: encodeVint(extraTimeMtime)}, {Type: 1, Body: encryptionRecordBody(fileEncCheckPresent, 0xAA)}]`
  — a time record declaring an mtime and carrying none of its bytes, then a valid encryption
  record. Get the block header with `readBlockHeader(bytes.NewReader(rar5Member(t, spec)))`, the
  pattern `file_header_refusal_test.go:83` uses, and call `parseFileHeader`. Assert
  `errors.Is(err, ErrCorruptFileHeader)` (from `parseTimeRecord`: `need` is 8, the body is empty);
  `fh != nil`; `fh.Encrypted`; `len(fh.Salt) == 16`; `len(fh.EncCheck) == 12`.
- [ ] **Step 3: confirm it fails** on `fh.Encrypted` being false.
- [ ] **Step 4: implement.**

```go
func parseExtraRecords(fh *FileHeader, extra []extraRecord) error {
	// Every record is parsed, and the first failure is returned once all of
	// them have run. parseBlockHeaderFields has already cut each record to its
	// own declared length and refused broken size or type framing, so one
	// record's bad body cannot desynchronise the next. Stopping at the first
	// failure let a malformed record placed ahead of the encryption record hide
	// it entirely, and the header reported an encrypted member as plaintext.
	var first error
	for _, e := range extra {
		var err error
		switch e.Type {
		case 1: // Encryption
			err = parseEncryptionRecord(fh, e.Data)
		case 2: // File hash (Blake2sp)
			err = parseHashRecord(fh, e.Data)
		case 3: // File times
			err = parseTimeRecord(fh, e.Data)
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}
```

- [ ] **Step 5: run the test, then the full suite.**
- [ ] **Step 6: mutation check** — restore `return err` inside the loop; the new test must fail.
- [ ] **Step 7: commit** `fix(rarengine): parse every extra record before reporting the first failure`.

---

## Task 2 — an encryption record's presence is recorded before its body is validated

**Files:** Modify `header.go` — `parseEncryptionRecord`. Test: `header_test.go`.

**Why:** `fh.Encrypted = true` (`header.go:353`) sits after the exits at `:340`
(`ErrUnknownEncryptMethod`) and `:351` (`ErrCorruptEncryptData`), so an encrypted member whose
record is malformed reports `Encrypted: false`. `:353` is the flag's only setter, so presence is
what it already means.

- [ ] **Step 1: failing tests.** Table-driven, `TestMalformedEncryptionRecordStillReportsEncrypted`,
  each case a member with one `{Type: 1, Body: ...}` extra record and `parseFileHeader` called on
  it:
  - unknown version — `encodeVint(1)` — want `ErrUnknownEncryptMethod`
  - too short for salt and IV — `encodeVint(0)`, `encodeVint(0)`, 10 bytes — want
    `ErrCorruptEncryptData`
  - check flag set, check value short — `encodeVint(0)`, `encodeVint(fileEncCheckPresent)`, 33
    bytes, 5 bytes — want `ErrCorruptEncryptData`

  Each asserts `fh != nil`, `errors.Is(err, want)` and `fh.Encrypted`. The third case passes today —
  it fails after `:353` — and is kept as the boundary, pinning that the other two are fixed by
  recording presence rather than by reordering the length checks.
- [ ] **Step 2: confirm the first two cases fail.**
- [ ] **Step 3: implement** — DELETE the existing `fh.Encrypted = true` at `header.go:353`, and
  make the assignment the first statement of `parseEncryptionRecord` instead (the comment below
  says it is the only setter, which is false while `:353` remains):

```go
	// Presence, not validity. This is the only place Encrypted is set, so the
	// flag means the archive carries an encryption record for this member --
	// true whether or not the body below parses. Set after the checks, a
	// malformed record reported an encrypted member as plaintext. A body that
	// fails still returns its error, and that error is what refuses the member
	// and keeps buildChain from ever deriving a key from the zero salt and IV
	// such a header is left with.
	fh.Encrypted = true
```

- [ ] **Step 4: tests, then the full suite.**
- [ ] **Step 5: mutation check** — move the assignment back below the length check; cases one and
  two must fail.
- [ ] **Step 6: commit** `fix(rarengine): report an encrypted member as encrypted when its record is malformed`.

---

## Task 3 — a header refused for its size still carries its extra records

**Files:** Modify `header.go` — `parseFileHeader` and its doc comment; `ErrUnpSizeUnknown`'s doc
comment. Modify `entry.go` — `Entry.Header`'s doc comment. Test: `header_test.go`,
`file_header_refusal_test.go`.

**Why:** the unknown-size and negative-size checks return before `parseExtraRecords` runs, so
those headers carry no extra-record fields at all.

- [ ] **Step 1: extract the refused-by-name assertion.** The same sequence is asserted four times
  — `TestRefusedExtraRecordMemberReportedByName` (`file_header_refusal_test.go:105`),
  `TestUnpSizeUnknownMemberRefusedByName` (`:310`), `TestNegativeUnpackedSizeMemberRefusedByName`
  (`:336`), and `TestUnknownUnpackedSizeIsRefusedByName` (`crc_verify_test.go:151-177`):
  `NextEntry` returns no error and a non-nil entry, `Header.Name` matches, and both `Read` and
  `Close` satisfy `errors.Is` for one sentinel. The fourth goes on to read a SECOND entry from the
  same `Reader`, so the helper takes the `Reader` rather than building one. Extract it:

```go
// assertRefusedByName reads the next entry of r and asserts it is the member
// name, refused: NextEntry hands it back rather than failing, and both Read and
// Close report want. It returns the entry, whose Header stays readable after
// Close. Exactly one entry is read -- a loop that searched for the name would
// pass even with a fabricated entry before it.
func assertRefusedByName(t *testing.T, r *Reader, name string, want error) *Entry {
	t.Helper()
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if e == nil || e.Header == nil {
		t.Fatalf("NextEntry returned %+v, want an entry for %q", e, name)
	}
	if e.Header.Name != name {
		t.Fatalf("Header.Name = %q, want %q (header %+v)", e.Header.Name, name, e.Header)
	}
	buf := make([]byte, 16)
	if _, readErr := e.Read(buf); !errors.Is(readErr, want) {
		t.Fatalf("Read error = %v, want %v", readErr, want)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, want) {
		t.Fatalf("Close error = %v, want %v", closeErr, want)
	}
	return e
}
```

  Rewrite all four tests to call it (`assertRefusedByName(t, NewReader(volumesOf(stream)), ...)`,
  or the test's existing `r` for the fourth, which keeps its second-entry assertions), keeping each
  test's own doc comment and fixture. The suite must stay green with no production change, and
  each rewritten test must go red on a probe naming the wrong member.
- [ ] **Step 2: failing tests.**
  - `TestSizeRefusalStillCarriesExtraRecords` in `header_test.go`, table over unknown size
    (`extraFileFlags: fileFlagUnpSizeUnknown`) and negative size (`unpackedSz: new(int64(-1))`),
    each with `extraRecords: {{Type: 1, Body: encryptionRecordBody(fileEncCheckPresent, 0xAA)}}`.
    Assert the existing sentinel (`ErrUnpSizeUnknown` / `ErrCorruptFileHeader`), `fh.Encrypted`,
    `len(fh.EncCheck) == 12`.
  - `TestSizeRefusalOutranksAnExtraRecordFailure` in `header_test.go`: unknown size with
    `{Type: 1, Body: encodeVint(99)}` wants `ErrUnpSizeUnknown` and NOT `ErrUnknownEncryptMethod`;
    negative size with the same record wants `ErrCorruptFileHeader` and NOT
    `ErrUnknownEncryptMethod`. Passes today and must keep passing: it pins that the reorder moves the
    PARSE and not the REPORT.
  - `TestRefusedMemberHeaderReportsEncryption` in `file_header_refusal_test.go`: the member is
    built with `rar5Member(t, memberSpec{..., extraFileFlags: fileFlagUnpSizeUnknown,
    extraRecords: []extraRecordSpec{{Type: 1, Body: encryptionRecordBody(fileEncCheckPresent,
    0xAA)}}})` — NOT a new hand-written byte builder alongside the three already in that file —
    wrapped in the archive and end headers from `testbuild_test.go`, then read through
    `assertRefusedByName(t, NewReader(volumesOf(stream)), name, ErrUnpSizeUnknown)`. Assert the
    returned entry's `Header.Encrypted`.
- [ ] **Step 3: confirm the first and third fail today, and the second passes.**
- [ ] **Step 4: implement.**

```go
	// Every extra record is attempted before either size check reports, so a
	// header refused for its size still carries what its archive encoded --
	// Encrypted above all. The ERRORS keep their priority: an unknown or
	// negative size outranks a failing extra record, so moving the parse up
	// changes no caller's verdict.
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
	return fh, nil
```

  The existing "Identity-first validation" comment above the size checks stays, with its
  "immediately before parseExtraRecords" corrected to "immediately after".
- [ ] **Step 5: docs.**
  - `parseFileHeader`'s doc comment: replace the paragraph from "Those two headers are NOT equally
    complete" through "and so is not done here". Name the THREE header-returning failures — unknown
    size, negative size, a failing or duplicated extra record — and state what a caller may rely on
    from such a header: `Name` and `Encrypted`. Every other field is either decoded correctly or,
    for fields belonging to the record that failed, zero or partly filled from that record.
  - `ErrUnpSizeUnknown`'s doc: drop "as produced by streamed archiving such as `rar -si`"; say the
    flag declares the unpacked size is not known.
  - `Entry.Header`'s doc: on an entry refused for its header, only `Name` and `Encrypted` are
    dependable — other fields may be zero or partly filled from a record that failed to parse.
    `Encrypted` reports that the member carries an encryption record, not that it is usable.
- [ ] **Step 6: tests, then the full suite.**
- [ ] **Step 7: mutation check** — restore the early size returns above `parseExtraRecords`; the
  first and third new tests must fail and the second must still pass.
- [ ] **Step 8: commit** `fix(rarengine): parse extra records before refusing a header's size`.

---

## Task 4 — each extra-record type may appear at most once

**Files:** Modify `header.go` — `parseExtraRecords`. Test: `header_test.go`,
`file_header_refusal_test.go`. Depends on Task 1 (same function) and Task 2 (the fourth case
asserts `Encrypted` on a malformed record).

**Why:** a pre-existing bug in the same class. `parseEncryptionRecord` writes `Salt`, `IV` and
`UseMac` unconditionally but `EncCheck` only when its flag is set, so two *valid* encryption records
build one header out of both, with a nil error. A crafted archive can clear `UseMac`, which makes
`verifyChecksum` (`entry.go:351`) compare a MAC as a CRC32 and report `ErrCRCMismatch` on a member
that decrypted correctly; or pair one record's check value with the other's salt, refusing a correct
password. Both are false accusations. Removing the class: a second record of any type this function
parses is a malformed header, refused, with the first record's fields kept. Real archives never carry
duplicates; unrar tolerates them by letting the last one win, which is exactly the mix above.

- [ ] **Step 1: failing tests.**
  - `TestDuplicateExtraRecordIsRefused` in `header_test.go`, table over the three types:
    - encryption: `[{1, encryptionRecordBody(fileEncCheckPresent|fileEncUseMac, 0xAA)}, {1, encryptionRecordBody(0, 0x55)}]`
    - hash: two `{2, ...}` records, each `encodeVint(0)` followed by 32 bytes (distinct fill)
    - time: two `{3, ...}` records, each a valid Unix mtime (`encodeVint(extraTimeMtime|extraTimeUnix)` + 4 bytes, distinct values)

    Each asserts `errors.Is(err, ErrCorruptFileHeader)` and that the FIRST record's values survived.
    For the encryption case specifically: `fh.UseMac` true, `fh.Salt[0] == 0xAA`,
    `len(fh.EncCheck) == 12`.
    - a fourth case, the first record malformed: `[{1, encodeVint(99)}, {1,
      encryptionRecordBody(fileEncCheckPresent, 0x55)}]`. Asserts `errors.Is(err,
      ErrUnknownEncryptMethod)` (the first failure stands; the duplicate does not replace it),
      `fh.Encrypted`, `fh.Salt == nil` and `fh.EncCheck == nil` — the second record is not parsed
      into the header. This case is the rule that the first record of a type is authoritative even
      when it failed.
    - a fifth case, an earlier failure of a DIFFERENT type: `[{3, encodeVint(extraTimeMtime)},
      {1, encryptionRecordBody(fileEncCheckPresent, 0xAA)}, {1, encryptionRecordBody(0, 0x55)}]`.
      Asserts `errors.Is(err, ErrCorruptFileHeader)` from the time record (its message does NOT
      contain "duplicate"), `fh.Salt[0] == 0xAA` and `len(fh.EncCheck) == 12`.
  - `TestDuplicateEncryptionRecordRefusesTheMember` in `file_header_refusal_test.go`: the
    encryption case above, built through `memberSpec.extraRecords`, read through
    `assertRefusedByName(t, NewReader(volumesOf(stream)), name, ErrCorruptFileHeader)`.
- [ ] **Step 2: confirm they fail today** — nil error, and `UseMac` false in the encryption case.
- [ ] **Step 3: implement.** `parseExtraRecords` becomes, with one "keep the first error" site:

```go
func parseExtraRecords(fh *FileHeader, extra []extraRecord) error {
	// [Task 1's comment, unchanged]
	//
	// A record type this function parses may appear once. Two encryption
	// records built one header out of both -- Salt, IV and UseMac from the
	// second, EncCheck from the first -- with a nil error, which let a crafted
	// archive clear UseMac and have a MAC compared as a CRC32, or pair one
	// record's check value with the other's salt. Refused rather than resolved
	// by choosing one: the header contradicts itself. The first record of a
	// type is the one parsed, even when it fails; a later one is never read
	// into the header.
	var first error
	var seen [4]bool // indexed by record type; 1-3 are the types parsed below
	for _, e := range extra {
		var err error
		if e.Type >= 1 && e.Type <= 3 && seen[e.Type] {
			err = fmt.Errorf("%w: duplicate extra record of type %d",
				ErrCorruptFileHeader, e.Type)
		} else {
			if e.Type >= 1 && e.Type <= 3 {
				seen[e.Type] = true
			}
			switch e.Type {
			case 1: // Encryption
				err = parseEncryptionRecord(fh, e.Data)
			case 2: // File hash (Blake2sp)
				err = parseHashRecord(fh, e.Data)
			case 3: // File times
				err = parseTimeRecord(fh, e.Data)
			}
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}
```

- [ ] **Step 4: tests, then the full suite** — including every test reading `testdata/*.rar`, which
  are real archives and must contain no duplicates.
- [ ] **Step 5: mutation check** — make the duplicate condition always false (parse every record);
  every case must fail, the fourth on `fh.Salt` being non-nil.
- [ ] **Step 6: commit** `fix(rarengine): refuse a header carrying the same extra record twice`.

---

## Docs commit — CLAUDE.md

A separate `docs(rarengine)` commit, no tests:
- The API paragraph already rewritten in the worktree: the public API may change when cleaner, a
  breaking change bumps the version (with a `/vN` module path past v1), and the small surface exists
  for safety, not stability.
- Line ~59: remove "and is the subject of a separate open issue" from the `r.volumes` sentence.
  That issue was #73, closed not-planned; the rest of the sentence stays.
- Add a Security Constraints bullet: **a header is never built from two records of the same type**,
  naming the `UseMac`/`EncCheck` mix and `TestDuplicateExtraRecordIsRefused`.

---

## Inconclusive / Deferred items

1. **An existing test may assert that parsing stops at the first failed record.** *Probe:* full
   suite after Task 1. *Branches:* none fail → proceed (a plan-review probe with all tasks applied
   found none); one fails expecting a later record's field to be zero → it encoded the defect, update
   it with a `Ruling:`; one fails otherwise → stop, the premise that records are independent is
   wrong.
2. **`TestNewMemberWithABadHeaderSurvivesTheContinuationScan` (`splice_test.go:355`) reports
   `Encrypted: true` after Task 2.** *Probe:* run it after Task 2. *Branches:* passes → the refused
   first block never reaches `splice.go:213` (the plan-review probe found it passes); fails → a
   refused member's `Encrypted` reaches the continuation identity check, stop and re-plan.
3. **The invariant above.** *Probe:* after Task 4, grep every production read of `Encrypted`, `Salt`,
   `IV`, `KdfCount`, `EncCheck` and `UseMac`, and confirm each is reached only on a nil
   `parseFileHeader` error. *Branches:* all confirmed → proceed; any reachable with an error → stop.
4. **A real archive might carry two records of one type.** *Probe:* the full suite after Task 4,
   which reads every `testdata/*.rar`. *Branches:* green → proceed; a real archive refused → stop,
   the "real archives never carry duplicates" premise is false and Task 4 needs re-planning.
5. **`parseHashRecord` silently ignores a too-short BLAKE2sp digest** (no error, `HasBlake2sp`
   false). Out of scope: `HasBlake2sp` selects only the wording of `ErrChecksumUnsupported`
   (`entry.go` `uncheckableDigest`), never a verdict. Recorded, not acted on.
6. **`UseMac` on a refused header reflects the record's validity, not its presence** — it is a flag
   inside the record, so it cannot be known when the record fails before its flags decode.
   Documented by Task 3's `Entry.Header` sentence (only `Name` and `Encrypted` are dependable), not
   changed.

---

## Carried-forward constraints

| # | Constraint | Source |
|---|---|---|
| C1 | Three header-returning failures: unknown size (`header.go:630`), negative size (`:633`), a failing extra record (`:641`). All three are covered. | Premise audit |
| C2 | `parseEncryptionRecord` exits at `:340`/`:351` before `fh.Encrypted = true` at `:353`, its only setter. | Premise audit, verified |
| C3 | A failing hash or time record placed BEFORE a valid encryption record hides it, because parsing stops at the first failure. | Adjudication, verified |
| C4 | For an archive with no duplicated extra-record type, no error any caller receives changes. Unknown size outranks negative size outranks an extra-record error. Duplicated types change errors by design (C14). | Gate 1 decision; narrowed by plan review round 2 |
| C5 | `Encrypted` means the member carries an encryption record, not that the record is usable. unrar decides decryption on `Encrypted` and refusal on `CRYPT_UNKNOWN`; here the error verdict does the refusing. | Gate 1, corrected by adjudication review |
| C6 | No new exported field or flag. A caller that ignores the verdict would ignore a flag; a caller that reads the verdict already gets the specific error. | Gate 1, corrected by adjudication review |
| C7 | Extra records are independent: `parseBlockHeaderFields` (`header.go:265-288`) cuts each to its own length and fails the block header on broken framing. | Verified |
| C8 | No production code reads encryption fields off a header returned with an error. | Premise audit; plan review ran it |
| C9 | Unknown-size members stay refused, even though unrar accepts them. | Gate 1, unrar comparison |
| C10 | `HasBlake2sp` selects only error wording, never a verdict. | Verified |
| C11 | Patch-level: no exported name or signature changes. | User, this session |
| C12 | `ErrUnpSizeUnknown`'s `rar -si` claim is contradicted by a measurement in #62. | Premise audit |
| C13 | No docs, comments, issue or PR text name a downstream consumer. | User, this session |
| C14 | A second record of any parsed type (1–3) is a malformed header, refused with `ErrCorruptFileHeader` unless an earlier record already failed (that error stands). The first record of a type is authoritative even when it failed; a later one is never parsed into the header. | User decision after plan review; clarified round 2 |
| C15 | On a refused header only `Name` and `Encrypted` are dependable; a record that fails at its check value has already written `Salt`/`IV`. | Plan review, verified at `header.go:353-357` |
| C16 | `encRecord` is removed, not kept beside the ordered list; its two call sites are rewritten. | Simplification + reuse lenses |
| C17 | The four refused-by-name tests (three in `file_header_refusal_test.go`, one at `crc_verify_test.go:151`) share one helper, `assertRefusedByName(t, r *Reader, name, want)`. | Reuse lens; count corrected round 2, verified |
