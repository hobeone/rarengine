# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`rarengine` is a zero-allocation, stream-oriented RAR5 decompression library in Go. It is designed for high-throughput Usenet downloaders (e.g., `gonzbd`) that decompress RAR5 streams on-the-fly from channels of `io.ReadCloser` volumes.

The public API surface is intentionally small, and is now **compiler-enforced** rather than merely documented: `NewReader`, `Reset`, `NextEntry`, `SetPasswords`, `Close`, plus `Entry`'s `Read`/`Close`/`Header`, `FileHeader`, the two inspection entry points `VerifyPassword` and `VolumeNumber`, and the exported error sentinels callers match on. Everything else is unexported. Keep it that way — anything new here is a contract this library has to hold forever.

`go doc` is the check: if it lists a symbol not named above, the surface has grown.

## Commands

```bash
# Build
go build ./...

# Tests (always with race detector before committing)
go test -race ./...

# Run a single test
go test -run TestName ./...

# Benchmarks
go test -bench=. -benchmem ./...

# Fuzz (run locally, not in CI)
go test -fuzz=FuzzHuffman ./...

# Format and resolve imports after every file edit
goimports -w .

# Adopt new language features
go fix ./...

# Lint
go vet ./...
golangci-lint run ./...
```

**Quality gate before every commit** — all five must pass:
```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
```

## Architecture

```
volumes <-chan io.ReadCloser
  └─ Reader          traversal: volumes, blocks, member admission, password
       └─ volume     one volume's bytes and the position within them
       └─ Entry      one member: reader chain, byte budget, CRC, verdict
            └─ decoder50 / storeReader
                 └─ cbcDecryptReader (if encrypted)
                      └─ multiVolumePayloadReader
```

`Reader.Close` is the only method another goroutine may call. It closes `done`, which is selected on at the volume receive — the one place this library can block unboundedly, since a channel with no sender and no close has no other end. `volMu` guards the `r.vol` pointer against that concurrent call and is taken once per volume, never per byte. It does NOT make the volume's contents concurrently safe: the splice holds `&v.body`, so guarding that would mean a lock per read. A `context.Context` reaches this library as `context.AfterFunc(ctx, func() { r.Close() })`, which is why nothing here takes one — `Entry.Read` reaches the same receive through the splice and must satisfy `io.Reader`, so a context parameter could never have covered the long operation.

`Reader` (`reader.go`) owns traversal only: which volume, which block, whether a member may begin. It does not own where the stream is — `volume` (`volume.go`) does, one instance per RAR volume, constructed fresh on every advance so a stale read position cannot outlive the volume it describes. It does not own how a member ended — `Entry` (`entry.go`) does: byte budget, running CRC, and a terminal verdict delivered by both `Read` and `Close` (`Close` reports `nil` on success). `splice.go` stitches a member's payload across a volume boundary; `crypto.go` holds the AES-256-CBC/PBKDF2 primitives; `errors.go` holds the exported sentinels.

The window (`window`, 32 MB sliding buffer, `window.go`) is allocated once in `NewReader` and shared by `storeReader`/`lz50Reader`. `Reset(false)` skips zeroing the buffer; eliminating the zero-loop removed an 81% CPU-time bottleneck.

Skipping the clear is safe only because `CopyBytes` refuses to read behind the history actually written since that reset — `window.historyLen()`, derived from `w` plus the `wrapped` lap flag. Without that bound a crafted stream can name a back-reference distance larger than the bytes its file has produced and read out the previous file's plaintext, which is still physically present in the buffer. The bound is load-bearing: it is what makes the missing memclr a performance choice rather than an information leak.

### Key files

| File | Role |
|---|---|
| `reader.go` | `Reader` — public API, traversal, block dispatch, password resolution |
| `volume.go` | `volume` — one RAR volume's byte stream and position within it |
| `entry.go` | `Entry` — sole owner of per-member state; byte budget, running CRC, terminal verdict |
| `splice.go` | splices a member's packed bytes across volumes |
| `crypto.go` | AES-256-CBC / PBKDF2 primitives |
| `errors.go` | exported error sentinels |
| `header.go` | RAR5 block/file/archive header parsing; `sanitizePath` for traversal protection |
| `decoder50.go` | LZ77 + Huffman decode loop (RAR5 method 1–5) |
| `huffman.go` | 10-bit direct-lookup Huffman table (do not replace with tree walk) |
| `bit_reader.go` | MSB-first bit reader; fetches up to 56 bits per call (bit-order contract is load-bearing) |
| `window.go` | 32 MB sliding LZ77 history; `Reset(bool)` — `false` skips memclr; `BeginFile`/`MarkIncomplete` own solid-history damage |
| `filters.go` | Post-decompression SIMD filters (E8/ARM branch relocation, delta) |
| `vint.go` | RAR5 variable-length integer encoding |

### Concurrency model

The library is **not concurrently safe** within a single `Reader` instance. Files within a single archive are decoded sequentially. See `TODO.md` for the analysis of when file-level parallelism is feasible (non-solid multi-file archives only).

### Zero-allocation invariants

- Do not instantiate `Reader` inside a loop — use `Reset(newChan)` to reuse the 32 MB window.
- Do not introduce heap allocations inside `NextEntry()` or `Entry.Read()` without a benchmark justifying the regression.
- Never reintroduce a zeroing loop on the window history buffer.

## Inspection entry points

`VerifyPassword` and `VolumeNumber` (`inspect.go`) answer two read-only questions traversal cannot: does this password match the archive's embedded check value, and where does this volume sit in its set. Both take an `io.Reader` positioned at the START and consume the signature themselves.

They exist because the header parsers they replace used to be exported, and were the only way to ask either question. A consumer had `readBlockHeader` plus `Parse{File,Archive,Crypt}Header` plus the `HeaderType*`/`ArcFlag*` constants — a parsing kit, from which a caller could hand a hand-built `blockHeader` straight to the decoders and bypass every format-level check. Two purpose-built answers replace it.

Both are subject to the traversal's own rules, because they walk blocks with no `volume` to do it for them: `skipPayload` advances past a block's declared payload (or the next header read lands on content), and a bare `io.EOF` before either question is answered is truncation, not a clean negative. A real archive never reaches that EOF — an unencrypted one answers at its first file header, an empty one at its end header — so only a cut stream does, and reporting it as "no password needed" would be the silent-truncation bug in another costume.

## Security Constraints

Structurally enforced — one sentence each, because a rule the type holds does not need prose telling a reader to hold it:

- Never let a block header be parsed out of a previous file's payload: `volume.next()` skips before reading, and the traversal has no other way to read a header.
- No block's declared payload survives into the next header read: same mechanism — the skip is unconditional and knows nothing about why a block was not claimed.
- Refusing a file means dropping its payload, whatever the reason for the refusal: same mechanism.
- The packed remainder is tracked per volume, never captured once, never read from a closed volume: `volume.body` is a field of `volume`, and an advance constructs a new `volume` rather than repointing one, so a stale count is unrepresentable.
- Trailing continuation blocks of an abandoned multi-volume file are cleanly drained: `Reader.NextEntry` discards headers where `!fh.FirstBlock`, and `volume.next()` drains their bodies automatically.
- A file's terminal error is durable for that file: `Entry.done`, set once, is returned by both `Read` and `Close`.

Carried forward — still a runtime guard, still needs a test:

- `sanitizePath` in `header.go` is mandatory for all archive-internal filenames — do not bypass it. Applied in the parser rather than at a write site, so every `FileHeader.Name` this library emits is already safe; this is defence in depth for a consumer that writes `fh.Name` directly, at the cost of destroying the evidence that an archive attempted traversal. The consumer that calls `Create` still owns the authoritative check — a library that writes no files cannot commit a traversal.
- The rar-bomb guard (`UnpackedSize > 1000 * PackedSize` for files > 1 MB) must not be weakened or removed without explicit user approval. It is now expressed as a terminal `Entry` (`terminalEntry` in `reader.go`), not a `refuse` call.
- The window history bound in `CopyBytes` (`distance > w.historyLen()`) must not be weakened or removed without explicit user approval. It is what keeps the deliberately-uncleared history buffer from being readable across files — see `window.wrapped` in `window.go`, which also enumerates the write paths that must maintain it.
- AES key material (password, derived key bytes, salt) must never appear in error messages or log output. Discipline, not structure, scoped to `crypto.go`.
- A file must never terminate cleanly without either meeting its declared `UnpackedSize` or reporting why not. `Entry.finish` is the only place that decides, and `ErrTruncatedFile` must not be made to satisfy `errors.Is(err, io.EOF)` — callers loop until `io.EOF`, so that would restore the silent-truncation bug it exists to prevent.
- **A header flag must never be able to switch verification off.** Every flag is attacker-supplied and none is cross-checked against what the entry actually contains, so gating the checksum on `IsDir` let a crafted archive deliver arbitrary bytes under a header claiming to be a directory. `Entry.verifyChecksum` gates on `e.size == 0` — the produced size, which this type enforces — never on `IsDir`, which the archive asserts and nothing cross-checks; `TestCRCVerificationIgnoresIsDir` pins this. Where a digest genuinely cannot be checked, it fails with `ErrChecksumUnsupported` rather than completing silently — and "cannot be checked" is decided by whether a comparison actually happened, not by which field the archive filled in: `UseMac`, a BLAKE2sp-only header (`rar -htb`, which records no CRC32), and a header recording no digest at all are one verdict, because two of them used to take the `!HasCRC32` return-nil path and complete as though verified. Verification is now unconditional: `SetVerifyCRC` is gone, and nothing a header says can turn it off. The `e.size == 0` gate must stay ABOVE every uncheckable-digest arm — while `UseMac` was tested first, an empty file or a directory inside an encrypted archive reported `ErrChecksumUnsupported` having produced no bytes at all; a member with nothing to check is not a member whose check was missed. `TestZeroLengthMemberIsCleanEvenWithAnUncheckableDigest` pins the ordering.
- **Sizes are validated where they are decoded.** A RAR5 size vint carries 70 bits, so it can set the sign bit of the `int64`. A negative size passes every "have we produced enough yet" comparison and panics the process at the slice clamp in `Entry.Read`. The parser rejects negative sizes, and `Read` tests `remaining <= 0` as the backstop. See "A length an archive declares is bounded in the type it was decoded in" below for the three declared *lengths* this rule did not originally reach.
- **Damage is recorded from what happened to the file, never from the error the caller receives.** The window's `incomplete` flag means "the window holds something other than what a solid successor's back-references assume". `window.MarkIncomplete` is the sole setter, called from two places: `Reader.finishActive`, from the outcome it observes on the member just abandoned (`e.short()`, or a `done` that is neither `io.EOF` nor `ErrChecksumUnsupported`), and `Reader.dispatch`'s refusal paths — a rar-bomb, a `BeginFile` failure, a failed `buildChain` — where a file is refused before it ever reaches `Entry`. A file refused before it decoded contributes nothing, same as one that ended short or failed its CRC32: all three damage the window whatever the caller is told about it.
- **A per-file header flag must be re-checked on every volume advance, not only at admission.** This now applies to RAR5: `Reader.nextVolumePayload` asserts `fh.Encrypted == e.Header.Encrypted` on every continuation block, returning `ErrCorruptFileHeader` on mismatch, so a member whose continuation claims encryption its first block did not cannot have that volume's bytes delivered verbatim as content.
- **A flag's name is not evidence of its value.** `FileHeader.Encrypted` was once derived from a bit that says eight salt bytes follow the name — a statement about header layout — rather than from the bit that says the member is encrypted. Every honest archive set both, so the two were indistinguishable in every test and fixture, and only a crafted archive separated them: one encrypted member reported `Encrypted` false and was decoded as though its ciphertext were content. The format that carried those two bits is gone from this library, but the rule is not: before keying a guard on a flag, read what the format says the bit *means*, not what the field is called.
- **A member cannot complete while a header saying it continues is in force.** Reaching the declared `UnpackedSize` means every byte has been produced; `LastBlock` false means the archive says more parts follow. `Entry.verifyChecksum` refuses that combination with `ErrCorruptFileHeader` before it reaches any digest, because the CRC32 field of a non-final part covers that part's packed bytes rather than the file's plaintext — comparing it reported `ErrCRCMismatch` on content that had decoded perfectly, which is the false accusation this library treats as worse than a missed check. Refused rather than skipped: `nil` would let a malformed entry complete silently, and `ErrChecksumUnsupported` would tell a caller whose policy is "accept unverifiable" that this is an archive class we cannot check, when it is an archive contradicting itself. Note that `LastBlock`'s zero value is `false`, so a hand-built `FileHeader` in a test claims a further part unless it says otherwise.

- **A malformed archive header ends traversal, wherever it is reached.** `Reader.handleNonFileBlock` wraps a failed `parseArchiveHeader` as `ErrCorruptArchiveHeader` (the underlying failure, typically `ErrTruncatedVint`, is still reachable through `errors.Is`), but it only wraps — it is `Reader.latchArchive` that records the error on `Reader.fatal`, so every later `NextEntry` call returns it again without touching `r.vol`. `NextEntry` calls `latchArchive` on its own scan loop's result, and `nextVolumePayload` (`splice.go`) calls it at every archive-level failure reached while splicing a member across a volume boundary, including the identical `parseArchiveHeader` failure reached there — an attacker chooses which path sees a truncated archive header only when both are wired to the same latch. `Reset` clears the latch. `io.EOF` and `ErrNoNextVolume` deliberately do NOT latch — they are ordinary end-of-archive signals, not failures. `ErrNoNextVolume` now surfaces in one place only: reached mid-member, through the splice, it is that member's verdict and says a part is missing. Running out of volumes with no member in progress is the archive being over, and `NextEntry` reports that as `io.EOF` — the one thing its doc comment promises, and previously not true, which is why every loop in the test suite had to check two sentinels.

- **A cut the traversal cannot vouch for must not end the archive cleanly.** `io.LimitedReader` reports `io.EOF` whether it delivered its whole count or the source ran out under it, so neither the scan nor the splice could tell a volume boundary from a truncation. Three mechanisms now separate them: `volume.next()` fails with a wrapped `io.ErrUnexpectedEOF` when the skip completes with `body.N > 0`; `multiVolumePayloadReader.Read` refuses to advance when `volume.bodyShort()` says the cut is inside THIS member's payload, which previously stitched a short volume onto the next one and reported the member complete; and `Reader.damaged` records a cut in any other block so that running out of volumes afterwards reports it in `io.EOF`'s place. The scan deliberately continues past a cut — the members beyond it are still readable, and a set arriving with a part missing is ordinary rather than exceptional — so the record of the damage is the only thing standing between that and a caller taking a set with a hole in it for a complete one.
- **A ring buffer's pointers are maintained by the write that moves them, not by a caller remembering to drain.** `window.writeBytes` stages bytes as unread and documents that callers "must drain via Read before w overruns r" — a contract `storeReader` structurally could not meet, because a stored member's bytes reach the caller straight from the source and it has no drain step at all. A stored member larger than the window lapped `r`, leaving `full` and `Available` describing a buffer that no longer existed. `window.recordHistory` is the primitive for bytes that are history but were never staged here: it writes and syncs `r` to `w`, so the invariant holds by construction. `window.Read` additionally breaks out of its copy loop when a copy moves nothing — with `full` stale it recomputed the same empty range forever, and a hang in a decompression library points the stack at `Read` rather than at whatever corrupted the state. Neither is reachable through the public API today: `BeginFile` resets `r` and clears `full` at every member boundary, and nothing reads the window during a stored member. `TestMemberBoundaryClearsStaleFull` pins that mask, because the reachability argument depends entirely on it.

- **A format version is checked before its data is decoded, and a declared capacity is not.** These look like the same rule and are opposites. RAR 7.0 raised the file header's unpack-version field and changed nothing a traversal can see from outside that field — same signature, same block framing, same vint encoding — so every member with a nonzero method went to the RAR5 decoder and produced garbage that only the CRC32 caught, after the whole member had been delivered. `Reader.dispatch` now refuses `fh.UnpackVersion != unpackVersionRAR5` with `ErrUnsupportedFormat`, before the bomb ratio and before `BeginFile` — and because `dispatch` only ever sees FIRST blocks, the continuation identity check in `nextVolumePayload` compares it too, or a member admitted as version 0 could continue as version 1 on the next volume. `testdata/rar7_unpack_version.rar` is a genuine rar 7.11 archive and `testdata/rar5_dict4g.rar` is the same archive one step below the boundary; both are ~105 bytes because the content is piped through `-si`, which stops rar shrinking the dictionary to the input size — see `generate.sh`, since neither is reproducible without that trick. The declared *dictionary size* is deliberately NOT checked the same way: `rar -md64m` on a 60 MB file declares a 64 MB dictionary — twice this library's window — and decodes correctly today, because the declared size is the encoder's maximum rather than a statement about the distances it used. Refusing on it would reject working archives. The real guard is `CopyBytes`'s `historyLen()` bound, which acts on the distance actually named by the stream. A version says what the bytes ARE; a capacity says what they MIGHT have needed.

- **Narrowing is not the hazard; signedness is.** `filterE8` runs its output position in `uint32`, matching unrar's `uint FileOffset=(uint)WrittenFileSize`. The narrowing is deliberate and exact: `fileSize` is 2^24 and 2^24 divides 2^32, so `(x mod 2^32) mod 2^24` equals `x mod 2^24`. With an `int32` position, Go's `%` returned a NEGATIVE remainder past 2 GB of output and the relocation came out 2^24 too small — except when the position landed on a multiple of 2^24, where it agreed by accident, which is why nothing caught it. `FilterArm` needs no equivalent change: only the low 24 bits are stored, and `(x mod 2^32)/4` agrees with `x/4` in those bits, so its `uint` is correct at both widths. The E8 sign tests are written against raw bits rather than a signed comparison for the reason unrar gives — they must not depend on a signed type's presence or width. `TestFilterE8MatchesUnrarAcrossOutputPositions` pins this against unpack50.cpp's algorithm transcribed literally, at offsets no committable fixture could reach.

- **A length an archive declares is bounded in the type it was decoded in.** A RAR5 vint carries 70 bits, so a name length, an extra-area size and an extra-record size can each be given a value whose `int` conversion is negative — which passes `len(payload) < int(v)` and then panics at the slice bound that check exists to guard. `parseFileHeader` and `parseBlockHeaderFields` compare `uint64(len(payload))` against the decoded `uint64` and convert only afterwards. This is the same rule as "sizes are validated where they are decoded", which was written narrowly around `UnpackedSize` and so did not cover the three lengths that reach a slice bound.

- **A continuation must prove it belongs to the member it is spliced into.** `nextVolumePayload` checks `Name`, `Method`, `Encrypted` and `UnpackVersion` against the first block's header on every volume advance. Only the `!FirstBlock` flag connected the two before, so a set presented out of order, or an archive built to interleave two members, had another file's payload delivered as this one's content with a nil error — and a method switch fed compressed bytes to the store reader the first block selected.

- **Nothing behind the end header belongs to the archive.** `handleNonFileBlock` closes the volume on `headerTypeEnd`, for both paths at once. Falling through to "not a file header, keep scanning" read whatever followed, and RAR volumes are routinely padded — so an archive whose members all arrived intact ended on `ErrBadHeaderCRC` instead of `io.EOF`.

- **The two header-reading paths differ only in what they do with a FILE block, and that is now the only thing they each say.** `Reader.dispatch` and `nextVolumePayload` both scan block headers; every non-file arm is `Reader.handleNonFileBlock` (`reader.go`), called by both. Restated per path, those arms disagreed three separate times in one change — an archive-header failure latched in one path and not the other, `HEAD_CRYPT` armed in `dispatch` alone (header-encrypted multi-volume archives were unreadable across a boundary), and a corrupt continuation header ending the whole archive in one path while costing one member in the other. Two of those were data loss. The helper returns no handled-flag: nothing there discards payload, `volume.next()` does that unconditionally, so an arm that does nothing is already correct and a per-case obligation to report handling would be the very thing that made the arms drift. Its two outputs are an unlatched archive-level error, which each caller latches on its own way out, and a nil `r.vol` meaning an end header closed this volume — `nextEntry` reads that at the top of its loop, the splice acts on it explicitly because it owns its own advance. The archive header's `Solid` flag reaching `r.solid` is pinned from both paths by `TestArchiveHeaderSolidFlagReachesTheReader`, since nothing the public API reports distinguishes a solid abandon from a non-solid one.

- **Pointing a shared decoder at a new member invalidates what the last one buffered.** `decoder50.init` clears `d.br` unconditionally. A member larger than half the window is not decoded to the end of its compressed block before the caller can abandon it, and `fill()` reads a non-nil `br` as "still inside a block" — so every member after an abandoned one decoded from its leftover bits, against the Huffman tables it left behind.

- **Reset discards an archive; it does not read one.** `Reader.Reset` calls `severActive` before anything else. A member spanning volumes bottoms out on `multiVolumePayloadReader`, which does not stop at a closed volume — it asks the `Reader` for the next one — so an entry the caller still held, and closing one is ordinary, pulled a volume off the NEW channel and ate the header at the front of it. `volume.Close` covers the single-volume case by zeroing the aliased body and cannot cover this one.

- **A refusal that cannot discard payload must end traversal, not merely report.** This constraint belongs to no one engine — it is about any traversal component that can leave the stream standing on unread, attacker-chosen bytes. Two mechanisms enforce it today: `volume.err`, sticky once a `volume.next()` call fails partway through either the payload skip or the following header read, so the same failure is returned on every later call without `v.rc` being touched again; and `Reader.fatal`, latched by `NextEntry` for every archive-level failure that leaves `r.vol` non-nil after it (a corrupt archive header, a header-encryption failure). Both exist because a stream position that cannot be vouched for must never be retried into — an earlier version of this rule was lost precisely because it was written as though it applied to one format's engine.

## Integration Testing

`integration_test.go` runs differential oracle tests against the system `unrar` binary. Test fixtures live in `testdata/`. The fuzz target for the Huffman decoder is in `huffman_test.go` (`FuzzHuffman`).

Hand-built archives come from `testbuild_test.go` and nowhere else. Four files used to construct RAR5 headers from raw bytes, so a format-level correction had to be found and applied in each — the count in issue #35 was wrong twice before it landed. There is now one signature (`rar5Sig`), one block wrapper (`rar5Block`), one archive/end header pair, and one file-header layout (`buildRAR5Member`). `memberSpec` is the descriptive way to reach that layout; `rar5FileEntry`/`rar5EntryComp`/`rar5EntryFlags` are a positional face over the same function, kept because their call sites read better with three arguments than a struct literal. `rar5BlockDeclaring` is deliberately not a member builder: it declares payload with no entry behind it, which is the shape the payload-discard tests attack and which nothing derived from a file can express.
