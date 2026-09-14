# Close vs the Signature-Read Window Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Reader.Close` able to reach — and therefore close — the volume stream that is being read for its RAR signature, closing the one window in which an owned stream is reachable from neither `r.vol` nor `r.volumes`.

**Architecture:** Ownership of the stream transfers at the channel receive, but reachability currently begins only at `publishVolume`, and the signature read happens between them. Rather than guard that gap with a second `Close`-visible field, this plan collapses it: `nextVolume` wraps the stream in a `*volume` and publishes it immediately, then reads the signature *through* the published volume. Ownership transfer and reachability become the same statement (`r.vol = v`), and the double-close that a concurrent `Close` now makes possible is absorbed by `volume.closeOnce`, which already exists for exactly that reason.

**Tech Stack:** Go 1.25+ (`testing/synctest`), no new dependencies.

**Spec:** Issue #74 and its two pinned comments — the premise-check verdict (`holds-with-correction`, with the corrected problem statement) and the Gate 1 record (three sketches, adjudication, and the objection this plan answers with Task 4).

## Global Constraints

- **Quality gate before every commit, all five:** `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
- **The public API surface is compiler-enforced and must not grow.** `go doc` must list exactly: `NewReader`, `Reset`, `NextEntry`, `SetPasswords`, `Close`, `Entry`'s `Read`/`Close`/`Header`, `FileHeader`, `VerifyPassword`, `VolumeNumber`, and the exported error sentinels. Nothing in this plan adds an exported symbol.
- **Conventional Commits 1.0.0.** Scope `rarengine`. Never `Step X.Y:`. Commit messages end with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- **In this worktree, edit with Edit/Write, never Bash.** The isolation guard rejects heredocs and `&&` chains.
- **Zero-allocation invariants hold.** No new allocation inside `NextEntry` or `Entry.Read` without a benchmark justifying it. `volume` is constructed once per volume advance, never per byte.
- **`volMu` discipline:** taken at volume transitions, never per byte. Every non-deferred unlock carries `// --- no lock held below this line ---` (`GEMINI.md:111`).
- **A caller's cancellation is never recorded as the archive's fault.** Already satisfied by `NextEntry`'s exit translation (`reader.go:242`) and `latchArchive`'s closed-Reader exemption; this plan adds no further mechanism for it, and an earlier draft that did was measured unobservable — see Task 2.

---

## File Structure

| File | Change |
|---|---|
| `volume.go` | Split `openVolume` into `newVolume` (construction) + `(*volume).readSignature` (validation). Add the `signed` phase flag and `next()`'s guard on it. Later, retire `openVolume`. |
| `reader.go` | `nextVolume` reordered to publish-then-validate. `Close`'s doc comment, `armHeaderDecryption`'s and `nextVolume`'s own corrected. |
| `discard_payload_test.go`, `volume_damage_test.go`, `splice_test.go`, `reader_encryption_test.go` | Stale comments naming `openVolume` or the old ordering. |
| `reader_close_test.go` | Two new `synctest` pins — `NextEntry`, and `Entry.Read` via the splice. |
| `volume_test.go` | The `signed`-guard pin; migration of 7 `openVolume` call sites. |
| `testbuild_test.go` | New `mustOpenVolume` helper; migration of 1 call site. |
| `verify_password_test.go` | Migration of 1 call site. |
| `CLAUDE.md` | The concurrency-model paragraph gains the acquisition window; the security-constraint list gains the `signed` guard. |

---

### Task 1: Split construction from validation

No behaviour change. This exists so Task 2's diff is a reordering a reviewer can read in one screen, rather than a reordering tangled with a refactor.

**Files:**
- Modify: `volume.go:97-102`

**Interfaces:**
- Consumes: nothing.
- Produces: `func newVolume(rc io.ReadCloser) *volume` and `func (v *volume) readSignature() error`. Task 2 calls both. `openVolume` keeps its exact current signature and behaviour, `func openVolume(rc io.ReadCloser) (*volume, error)`, and is retired in Task 5.

- [ ] **Step 1: Verify the baseline is green**

Run: `go test -race ./...`
Expected: PASS. If not, stop — the tree was not clean when this task started.

- [ ] **Step 2: Replace `openVolume`'s body with the composition**

In `volume.go`, replacing the existing `openVolume`:

```go
// newVolume wraps rc as the Reader's open volume WITHOUT consuming anything
// from it. The stream is positioned at byte 0 -- v.readSignature must run
// before v.next(), and v.signed is what enforces that.
//
// Split from the signature read so a volume becomes reachable from the Reader
// at the instant its stream is received, rather than after a blocking read
// that Reader.Close could not reach. See nextVolume.
func newVolume(rc io.ReadCloser) *volume {
	return &volume{rc: rc}
}

// readSignature consumes and validates the RAR5 signature on v's own stream,
// leaving v positioned on the first block boundary.
//
// A failure here does not set v.err: v.err means "v.rc is at an offset next()
// cannot vouch for", and a volume that failed its signature is discarded by
// its caller rather than retried. Setting it would be harmless but would
// claim a sticky position-level failure this is not.
func (v *volume) readSignature() error {
	if err := readSignature(v.rc); err != nil {
		return err
	}
	v.signed = true
	return nil
}

// openVolume reads and validates the RAR5 signature, leaving v positioned on
// the first block boundary. A RAR3 signature is recognised only so it can be
// reported as ErrUnsupportedFormat by name; nothing past the signature is
// parsed.
func openVolume(rc io.ReadCloser) (*volume, error) {
	v := newVolume(rc)
	if err := v.readSignature(); err != nil {
		return nil, err
	}
	return v, nil
}
```

**Note:** `v.signed` does not exist yet — it is added in Task 4. Until then, delete the `v.signed = true` line from `readSignature` and add it back in Task 4.

Deferring it keeps each commit's diff about one thing; it is **not** required by the linter. A write-only field with no reader was probed against this repo's `.golangci.yml` and `golangci-lint run ./...` reported 0 issues, so adding the field early would also pass the gate. Do not repeat the "the `unused` linter rejects it" rationale an earlier draft of this plan carried — it is false, and a false reason in a plan outlives the step it justified.

- [ ] **Step 3: Run the full suite**

Run: `go test -race ./...`
Expected: PASS, unchanged. This task changes no behaviour; a failure here means the composition is not equivalent.

- [ ] **Step 4: Run the quality gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add volume.go
git commit
```

Message:
```
refactor(rarengine): split volume construction from signature validation

newVolume wraps a stream without reading it; (*volume).readSignature
consumes the signature through an existing volume. openVolume is now
their composition and behaves identically.

Preparation for making the signature read happen through a volume the
Reader can already reach.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

---

### Task 2: Publish before validating

The fix. After this task `Reader.Close` reaches the stalled stream on all three caller paths.

**Files:**
- Modify: `reader.go` (`nextVolume`, ~1048-1085)
- Test: `reader_close_test.go`

**Interfaces:**
- Consumes: `newVolume`, `(*volume).readSignature` from Task 1.
- Produces: no new symbols. `nextVolume` keeps its signature `func (r *Reader) nextVolume() error`.

- [ ] **Step 1: Write the failing test**

Append to `reader_close_test.go`:

```go
// Close must reach a stream that is stalled inside its own signature read.
//
// The window this pins is the gap between the channel receive and the volume
// becoming reachable as r.vol. A stream received but not yet published is
// reachable from neither r.vol nor r.volumes, so Close -- which reads exactly
// those two -- could not close it, and never called Close on it at all. That
// is not the documented "your stream's Close must interrupt its own Read"
// limit: stalledVolume models os.File/net.Conn, whose Close DOES interrupt an
// in-flight Read, and it was still never rescued.
//
// Mutation check: move the readSignature call in nextVolume back above
// publishVolume and this deadlocks inside the bubble.
func TestCloseRescuesAStreamStalledInItsSignatureRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Constructed INSIDE the bubble, as every test in this file is: a
		// channel created outside leaves the block non-durable and Wait
		// never returns.
		release := make(chan struct{})
		sv := &stalledVolume{release: release}

		volumes := make(chan io.ReadCloser, 1)
		volumes <- sv
		r := NewReader(volumes)

		result := make(chan error, 1)
		go func() {
			_, err := r.NextEntry()
			result <- err
		}()

		// Blocks durably inside io.ReadFull, which is the state under test.
		synctest.Wait()
		_ = r.Close()

		// No timeout arm: inside a bubble a Close that fails to release is
		// reported as a deadlock, which cannot pass by accident on a slow
		// machine.
		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("NextEntry = %v, want ErrReaderClosed", err)
		}
		if !sv.closed() {
			t.Fatal("the stalled stream was never closed by the library -- " +
				"Close reached neither r.vol nor r.volumes for it")
		}
	})
}

// stalledVolume models an os.File/net.Conn-class stream: its Read blocks
// until released, and its own Close releases it. This is the class Close's
// doc comment says IS rescuable, which is what makes it the right fixture --
// a stream that ignores a concurrent Close would leave the test unable to
// distinguish the library's defect from the stream's limitation.
type stalledVolume struct {
	release chan struct{}
	mu      sync.Mutex
	didClose bool
}

func (s *stalledVolume) Read(p []byte) (int, error) {
	<-s.release
	return 0, os.ErrClosed
}

func (s *stalledVolume) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.didClose {
		s.didClose = true
		close(s.release)
	}
	return nil
}

func (s *stalledVolume) closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.didClose
}
```

- [ ] **Step 2: Run it and verify it fails as a deadlock**

Run: `go test -race -run TestCloseRescuesAStreamStalledInItsSignatureRead ./...`
Expected: FAIL with `panic: deadlock: all goroutines in bubble are blocked`, with `readSignature` / `openVolume` / `nextVolume` on the reported stack. A failure of any other shape means the fixture is not reaching the window — fix the fixture before proceeding.

- [ ] **Step 3: Reorder `nextVolume`**

Replace everything in `reader.go`'s `nextVolume` from the `rc == nil` check onward:

```go
	if rc == nil {
		// A nil element on the channel is the caller's bug, but the library
		// must report it rather than dereference it: the signature read
		// would go straight at a nil interface and take the process down.
		return errors.New("rarengine: nil volume stream on the volumes channel")
	}
	// Published BEFORE the signature is read, which is the whole point. The
	// stream is owned from the receive above, and until it is reachable from
	// r.vol a concurrent Close can reach neither it nor the channel it has
	// already left -- so a stream that stalls inside its signature read could
	// never be closed, and the traversal goroutine parked in it could never
	// be rescued. Publishing first makes ownership and reachability the same
	// statement rather than two moments with a blocking read between them.
	//
	// The double close this admits -- Close reaching v while this function
	// also closes it below -- is absorbed by volume.closeOnce, which exists
	// for exactly that reason. A bare io.ReadCloser has no such guarantee
	// (io.Closer leaves a second Close undefined), which is why the stream is
	// wrapped before it is published rather than parked in a field of its
	// own.
	v := newVolume(rc)
	if !r.publishVolume(v) {
		return ErrReaderClosed
	}
	if err := v.readSignature(); err != nil {
		// takeVolume clears r.vol unconditionally, so the documented
		// "every failure leaves r.vol nil" lifetime survives the reorder.
		r.closeCurrentVolume()
		return err
	}
	return nil
```

**No `isClosed()` arm here, deliberately — an earlier draft had one and it was measured unobservable.** The reasoning that produced it was that a `Close` interrupting the read would surface as `io.ErrUnexpectedEOF`, which `openNextVolume` skips as a damaged volume, recording `r.damaged`. Both halves were false:

- `io.ReadFull` converts to `io.ErrUnexpectedEOF` only when `n > 0 && err == io.EOF`. A stream closed before delivering a byte returns `n == 0` and its own error, which `signatureReadError` (`volume.go:88`) passes through verbatim. Measured across four classes — `os.ErrClosed`, `io.ErrClosedPipe`, `net.Conn`'s closed-connection error, `os.File`'s — none satisfies `errors.Is(err, io.ErrUnexpectedEOF)`, so the retry arm is not even reached.
- For the one class where it *is* reached (a `Read` returning bare `io.EOF` after close), the caller-facing **verdict** is identical with and without the arm: `NextEntry`'s translation (`reader.go:242`) turns any scan error into `ErrReaderClosed` while the Reader is closed, and `errors.Is(err, ErrReaderClosed)` held in **400 of 400** measured runs.

**What differs, stated exactly.** `r.damaged` is read at `reader.go:380`, on the `ErrNoNextVolume` branch, and a closed Reader **does** reach it when the producer has also closed `r.volumes` — both select cases are then ready and Go chooses at random. Measured over 400 runs: bare `ErrReaderClosed` 213 times, `"reader is closed: scan ended on: unexpected EOF: volume ended inside its signature"` 187 times. So the sentinel is stable and the `%v` tail is nondeterministic. That is acceptable — the tail carries more information, not less, and nothing matches on it — but do not write that the branch is unreachable. An earlier draft of this plan did, and it was measured false.

Deleting the arm costs one extra loop iteration whose `select` either takes `<-done` or receives a late-sent volume. Measured (`late volume: reads=0 closes=1`): that volume is **closed and never read** — with the arm it would have been left unclosed, because the arm returns before the retry iteration receives it. So the deletion is a small improvement on stream hygiene, not merely neutral.

- [ ] **Step 4: Run the new test and the full suite**

Run: `go test -race -run TestCloseRescuesAStreamStalledInItsSignatureRead ./...`
Expected: PASS.

Run: `go test -race ./...`
Expected: PASS. Pay attention to `TestCloseUnblocksAReaderWaitingForAVolume` and the empty-volume skip tests — both traverse this function.

- [ ] **Step 5: Run the quality gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add reader.go reader_close_test.go
git commit
```

Message:
```
fix(rarengine): let Close reach a volume stalled in its signature read

nextVolume published a volume only after openVolume had read its
signature, so a stream that stalls inside that read was reachable from
neither r.vol nor r.volumes and Close never called Close on it -- not
even for an os.File/net.Conn-class stream whose Close does interrupt an
in-flight Read. The traversal goroutine parked there could not be
rescued.

The volume is now published before the signature is read, making
ownership transfer and reachability the same statement. The double close
that admits is absorbed by volume.closeOnce.

Fixes #74

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

---

### Task 3: Pin the splice path

Task 2's fix is at the single acquisition site, so `Entry.Read` should already be rescued. "Should" is the reason this task exists: the claim that one fix covers three callers is exactly the kind of claim that is broader than its mechanism, and it costs one test to make it evidence.

**Files:**
- Test: `reader_close_test.go`

**Interfaces:**
- Consumes: `stalledVolume` from Task 2; `rar5Archive`/`rar5Member`/`memberSpec` from `testbuild_test.go`.
- Produces: nothing.

- [ ] **Step 1: Write the test**

```go
// Entry.Read reaches the same acquisition site through the splice, so the
// same stall is reachable while a member is mid-stream. This is the case a
// context parameter could never have covered: Entry.Read satisfies io.Reader.
//
// Mutation check: this is covered by Task 2's mechanism, so reverting that
// reorder turns this red too (measured: bubble deadlock). It is kept because
// "one fix covers three callers" is a claim about three callers, and this
// test is the only evidence for the second of them -- Reset, the third, is
// covered by contract rather than by any test.
func TestCloseRescuesASpliceStalledInASignatureRead(t *testing.T) {
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa",
		unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		sv := &stalledVolume{release: release}

		volumes := make(chan io.ReadCloser, 2)
		volumes <- &mockReadCloser{bytes.NewReader(v1)}
		volumes <- sv

		r := NewReader(volumes)
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}

		result := make(chan error, 1)
		go func() {
			_, err := io.ReadAll(e)
			result <- err
		}()

		synctest.Wait()
		_ = r.Close()

		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("Entry.Read = %v, want ErrReaderClosed", err)
		}
		if !sv.closed() {
			t.Fatal("the continuation volume stalled in its signature read " +
				"was never closed by the library")
		}
	})
}
```

- [ ] **Step 2: Run it**

Run: `go test -race -run TestCloseRescuesASpliceStalledInASignatureRead ./...`
Expected: PASS on the first run — Task 2's fix already covers this path. If it FAILS, that is a finding against the plan's "one fix covers three callers" premise; stop and report per the discovery contract.

- [ ] **Step 3: Confirm the mutation**

Temporarily move the `v.readSignature()` call back above `publishVolume` **in a scratchpad copy of the tree, never in place**, and confirm this test deadlocks. Restore.

- [ ] **Step 4: Quality gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add reader_close_test.go
git commit -m "test(rarengine): pin Close rescuing a splice stalled in a signature read"
```

---

### Task 4: Make the unvalidated window unrepresentable

Task 2 leaves `r.vol` briefly pointing at a volume whose signature has not been read. Today nothing can observe it: every traversal-side read of `r.vol` is on the traversal goroutine, which is blocked inside `nextVolume` for the whole window, and the only concurrent reader is `Close`, which calls nothing but `v.Close()`. That safety rests on a convention spanning three files, not on the type. A future change that makes volume acquisition concurrent — prefetch, which `TODO.md` contemplates — would make `v.next()` read a block header out of the signature bytes.

**Files:**
- Modify: `volume.go` (the `volume` struct, `readSignature`, `next`)
- Test: `volume_test.go`

**Interfaces:**
- Consumes: `(*volume).readSignature` from Task 1.
- Produces: `volume.signed bool`, unexported, read only by `next()`.

- [ ] **Step 1: Write the failing test**

Append to `volume_test.go`:

```go
// A volume whose signature has not been consumed must refuse to produce a
// header, rather than parse one out of the signature bytes.
//
// nextVolume publishes a volume before reading its signature, so r.vol points
// at an unvalidated volume for the duration of that read. Nothing can observe
// it today -- the traversal goroutine is the only reader and it is the one
// blocked inside the read -- but "unreachable by convention" and
// "unrepresentable" are different guarantees, and the one this codebase asks
// for is the second. Concurrent volume prefetch is the change that would turn
// the convention false without touching nextVolume at all.
//
// Mutation check: delete the !v.signed arm in next() and this reports a
// header parsed from the signature bytes (or ErrBadHeaderCRC) instead of
// ErrVolumeNotValidated.
func TestUnvalidatedVolumeRefusesToProduceAHeader(t *testing.T) {
	stream := append(append([]byte{}, rar5Signature...), rar5EndHeader()...)
	v := newVolume(&mockReadCloser{bytes.NewReader(stream)})

	if _, err := v.next(); !errors.Is(err, errVolumeNotValidated) {
		t.Fatalf("next() on an unvalidated volume = %v, want "+
			"errVolumeNotValidated -- it must not read a header out of the "+
			"signature bytes", err)
	}

	// And it works normally once validated, so the guard gates the phase
	// rather than the volume.
	if err := v.readSignature(); err != nil {
		t.Fatalf("readSignature: %v", err)
	}
	if _, err := v.next(); err != nil {
		t.Fatalf("next() after readSignature: %v", err)
	}
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `go test -race -run TestUnvalidatedVolumeRefusesToProduceAHeader ./...`
Expected: FAIL to COMPILE, because `errVolumeNotValidated` does not exist yet (`newVolume` does — Task 1 added it).

**Read the compiler error before accepting it.** A compile failure is a weak expectation: it swallows a typo in a helper name just as readily as the missing sentinel. The error must name `errVolumeNotValidated` and nothing else. `rar5EndHeader()` takes no arguments (`testbuild_test.go:66`) and `rar5Block` takes exactly one (`testbuild_test.go:33`) — an earlier draft of this step called `rar5Block(headerTypeEnd, nil)`, which would have failed to compile for the wrong reason and been recorded as the expected failure.

- [ ] **Step 3: Add the field, the sentinel, and the guard**

In `volume.go`'s struct, beside `err`:

```go
	// signed records that readSignature has consumed the RAR signature from
	// rc, so next() may read a block header. nextVolume publishes a volume
	// BEFORE reading its signature -- that is what lets Reader.Close reach a
	// stream stalled in that read -- which means r.vol briefly points at a
	// volume positioned at byte 0.
	//
	// Nothing can observe that today: the traversal goroutine is r.vol's only
	// reader and it is the goroutine blocked inside the read, and Close
	// touches nothing but Close(). This flag is what makes the guarantee
	// structural rather than conventional, because the convention is one
	// concurrency change away from false -- volume prefetch would let a
	// reader reach r.vol mid-read, and next() would then skip nothing (body.N
	// is 0) and parse a block header straight out of the signature bytes.
	//
	// Written by readSignature only, read by next() only, both on the
	// traversal goroutine. Not concurrency state: it is never read under
	// volMu and Reader.Close never touches it.
	signed bool
```

An unexported sentinel beside it (NOT an exported error — the public surface must not grow):

```go
// errVolumeNotValidated reports a volume asked for a header before its
// signature was consumed. Unexported: it is unreachable through the public
// API by construction, and an exported sentinel would be a contract this
// library has to hold forever for a state a caller cannot produce.
var errVolumeNotValidated = errors.New("rarengine: volume used before its signature was read")
```

The guard, at the head of `next()` above the `v.err` check:

```go
func (v *volume) next() (*blockHeader, error) {
	if !v.signed {
		return nil, errVolumeNotValidated
	}
	if v.err != nil {
		return nil, v.err
	}
```

Restore the `v.signed = true` line in `readSignature` that Task 1's note deferred.

- [ ] **Step 4: Run the test and the full suite**

Run: `go test -race -run TestUnvalidatedVolumeRefusesToProduceAHeader ./...`
Expected: PASS.

Run: `go test -race ./...`
Expected: PASS. Every existing test reaches a volume through `openVolume`, which validates, so none should trip the guard. A failure here identifies a path that reads a header without a signature — a finding, not a test to relax.

- [ ] **Step 5: Confirm the mutation in a scratchpad copy**

Delete the `!v.signed` arm in the copy. Expected: `TestUnvalidatedVolumeRefusesToProduceAHeader` FAILS with `next() on an unvalidated volume = unexpected EOF`.

Measured, so do not expect the message this plan's earlier draft predicted ("a header parsed from the signature bytes, or `ErrBadHeaderCRC`"). The fixture is an 8-byte signature plus a short end header — too small to fabricate a header from, so `readBlockHeader` runs out of bytes before any CRC is computed. The mutation is still red; only the reason differs.

- [ ] **Step 6: Quality gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add volume.go volume_test.go
git commit
```

Message:
```
fix(rarengine): refuse a header from a volume whose signature is unread

nextVolume publishes a volume before reading its signature, so r.vol
briefly points at a volume positioned at byte 0. Nothing observes it
today -- the traversal goroutine is its only reader and it is the one
blocked inside that read -- but the guarantee was conventional rather
than structural, and concurrent volume prefetch would falsify the
convention without touching nextVolume.

next() now refuses an unvalidated volume instead of skipping nothing
(body.N is 0) and parsing a block header out of the signature bytes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

---

### Task 5: Retire `openVolume`

`openVolume` now has no production caller — traversal uses `newVolume` + `readSignature`, and `inspect.go` uses the free `readSignature(io.Reader)` function. It survives only for 9 test call sites, and a production function kept alive by tests is a function a reader has to check for callers before trusting anything about it.

**Files:**
- Modify: `volume.go` (delete `openVolume`)
- Modify: `testbuild_test.go` (add `mustOpenVolume`, migrate **1** call site — line 372)
- Modify: `volume_test.go` (migrate **7** call sites — lines 37, 68, 89, 101, 152, 174, 206)
- Modify: `verify_password_test.go` (migrate **1** call site — line 23)

**Interfaces:**
- Consumes: `newVolume`, `(*volume).readSignature`.
- Produces: `func mustOpenVolume(t *testing.T, rc io.ReadCloser) *volume` in `testbuild_test.go`.

- [ ] **Step 1: Add the helper**

In `testbuild_test.go`, where CLAUDE.md says well-formed RAR5 framing lives:

```go
// mustOpenVolume builds a validated volume from rc, the way traversal does.
//
// Replaces the production openVolume, which traversal stopped calling when
// the signature read moved behind publishVolume. A test that wants a volume
// positioned on its first block wants exactly this; a test that wants an
// UNVALIDATED volume calls newVolume directly and says why.
func mustOpenVolume(t *testing.T, rc io.ReadCloser) *volume {
	t.Helper()
	v := newVolume(rc)
	if err := v.readSignature(); err != nil {
		t.Fatalf("readSignature: %v", err)
	}
	return v
}
```

- [ ] **Step 2: Migrate all 9 call sites**

Find them: `grep -n 'openVolume(' *_test.go` — expect 9 across `volume_test.go` (7), `testbuild_test.go` (1), `verify_password_test.go` (1). If the per-file split differs from that, the tree moved under this plan; re-derive before editing rather than trusting these line numbers.

Each site currently reads:

```go
	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
```

and becomes:

```go
	v := mustOpenVolume(t, &mockReadCloser{bytes.NewReader(stream)})
```

**Exception 1 — sites that assert failure.** A site asserting `openVolume` *fails* (a bad signature, a RAR3 stream, a truncated one) must NOT use the helper — it needs the error. Rewrite as `newVolume(...)` then `v.readSignature()` and assert on that. `TestOpenVolumeRefusesRAR3` (`volume_test.go:85-91`) is one of these, and its **name and failure string also name the deleted function** — rename it `TestReadSignatureRefusesRAR3` rather than leaving a test named after something that no longer exists.

**Exception 2 — `verify_password_test.go:23` is not the uniform shape.** It reads:

```go
	if _, err := openVolume(f); err != nil {
		t.Fatalf("openVolume: %v", err)
	}
```

The volume is **discarded** — the test then reads block headers straight off `f` via `readBlockHeader(f)`. The mechanical rewrite `v := mustOpenVolume(t, ...)` yields `declared and not used` and will not compile. What this site actually wants is the free function:

```go
	if err := readSignature(f); err != nil {
		t.Fatalf("readSignature: %v", err)
	}
```

Check every site before converting; `grep -n 'openVolume' *_test.go` and read the surrounding assertion rather than assuming the shape.

- [ ] **Step 3: Delete `openVolume`**

Remove the function from `volume.go`. Move its doc comment's surviving content (the RAR3 note) onto `(*volume).readSignature`, which now owns that behaviour.

- [ ] **Step 4: Verify nothing references it**

Run: `grep -rn 'openVolume' --include='*.go' .`
Expected: no matches except `mustOpenVolume`.

Run: `go test -race ./... && golangci-lint run ./...`
Expected: PASS.

This task is **optional and independently rejectable** — that is why it is last but one. `golangci-lint run ./...` was measured at the end-of-Task-2 state, with `openVolume` having test callers only: **0 issues**, so `unused` does not fire and nothing downstream depends on this task landing. A reviewer who prefers keeping `openVolume` can drop this commit without unpicking Tasks 1-4.

- [ ] **Step 5: Quality gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add volume.go testbuild_test.go volume_test.go verify_password_test.go
git commit -m "refactor(rarengine): retire openVolume in favour of a test helper"
```

---

### Task 6: Correct the documentation this change falsifies

**Thirteen** doc claims across eight files go stale. Most name `openVolume` or assert the ordering this plan inverts. Enumerated here because the majority sit in files no other task opens, so nothing would surface them.

**Files:**
- Modify: `reader.go` (`Close`'s doc comment ~905 and ~952; `armHeaderDecryption` ~270; `nextVolume`'s own doc ~1040)
- Modify: `volume.go` (`readSignature`'s doc ~107)
- Modify: `discard_payload_test.go` (~288), `volume_damage_test.go` (~93, ~99), `splice_test.go` (~415), `reader_encryption_test.go` (~156), `volume_test.go` (~232)
- Modify: `CLAUDE.md` (concurrency model; security constraints)

**Interfaces:** none.

- [ ] **Step 0: Fix the comments that this change makes false**

`discard_payload_test.go:288` is the urgent one: it says *"nextVolume assigns r.vol only once openVolume has succeeded"* — directly inverted by Task 2 — and it is the doc comment of `TestBadMagicLeavesNoUsableVolume`, the test guarding the very invariant being reordered. A false comment on the guarding test is worse than a false comment anywhere else.

`volume_damage_test.go:93,99` carry a **mutation-check instruction** naming `openVolume` ("return the bare error from openVolume's signature reads"). After Task 5 that function does not exist, so the instruction cannot be followed. Rewrite it against `(*volume).readSignature`.

Five more (`reader.go:270`, `volume.go:107`, `splice_test.go:415`, `reader_encryption_test.go:156`, `volume_test.go:232`) plus `discard_payload_test.go:286` are dangling references to a deleted function. Re-point each at `newVolume`/`(*volume).readSignature`.

Two further sites state the *lifetime* claim that Task 2 converts into a per-exit rule, and both must be corrected or the pair drifts — CLAUDE.md's own "restated per path, those arms disagreed three separate times" lesson:

- **`reader.go:890-896`, `closeCurrentVolume`'s doc.** It says "for the **four** callers that need no done channel" and "**All four are spent-volume closes**". Task 2 adds a fifth, and it is a *failed-acquisition* close rather than a spent-volume one. Both sentences go false.
- **`reader.go:20-25`, the `vol` field doc.** It restates independently that "`takeVolume` clears the field before the receive and `publishVolume` is the only thing that sets it, so there is nothing for a failure to leave behind" — the same claim as `nextVolume:1040`, which Step 0 already corrects. Correct both, in the same terms.

Also update `nextVolume`'s own doc comment (`reader.go:1040`), which currently claims *"Every failure leaves r.vol nil, which is a lifetime rather than a rule: takeVolume clears the field up front and publishVolume is the only thing that sets it again, so a failed advance has nothing to leave behind."* After Task 2 the property still holds, but one exit — the signature-failure path — now maintains it by calling `closeCurrentVolume` rather than by never having set the field. Say so plainly: it is a rule at that one exit and a lifetime everywhere else, and a future third exit added between `publishVolume` and `return nil` must call `closeCurrentVolume` too.

- [ ] **Step 1: Correct `Close`'s doc comment**

It currently promises Close "closes the volume currently open and every volume already queued on the channel". Before this change a stream in the acquisition window was **neither**, which is precisely the defect. After it, the volume currently open covers it — but only because publication now happens first, so say that:

```go
// It closes the volume currently open -- including one that has been
// published but whose signature is still being read, which is what makes a
// stalled acquisition escapable -- and every volume already queued on the
// channel.
```

- [ ] **Step 2: Correct the in-Read limitation paragraph**

`reader.go:952` says unblocking a stalled read "depends on that stream's own Close being safe to call while a Read is in flight". That remains true, but it presupposed the library reaches that Close, and in this window it did not. Add one sentence naming the distinction, because it is the distinction that made the bug invisible:

```go
// That limit is about whether closing the stream unblocks it. It is not a
// licence to leave a stream unreachable: until the signature read moved
// behind publishVolume, an os.File-class stream -- one whose Close DOES
// interrupt an in-flight Read -- was never rescued either, because Close
// never reached it to try.
```

- [ ] **Step 3: Update CLAUDE.md's concurrency paragraph**

The paragraph asserting `volMu` orders `r.done` and `r.vol` is still accurate. Add, after the sentence about `r.vol` having one writer:

> A volume becomes reachable as `r.vol` at the instant its stream is received, not after its signature has been read — the acquisition window in which an owned stream was reachable from neither `r.vol` nor `r.volumes` is what made a stalled signature read unescapable, and collapsing it is why `newVolume` and `(*volume).readSignature` are separate. `volume.signed` is what keeps the resulting unvalidated window unrepresentable rather than merely unobserved.

- [ ] **Step 3b: Document that `Close`'s return value changed in this window**

Previously a `Close` landing in the acquisition window found `r.vol == nil` and returned `nil`. It now finds the published volume and returns `v.Close()`'s result — the caller's own stream's `Close` error. `TestCloseClosesOpenAndQueuedVolumes` asserts `r.Close()` returns nil and still passes, because its fixtures return nil, so nothing fails; the behaviour change is real and silent. One sentence on `Close`'s doc comment.

- [ ] **Step 4: Add the security constraint**

To CLAUDE.md's structurally-enforced list:

Keep the wording narrow — "cannot produce a header", not "is valid". The guard covers `next()` only; `payload()`, `bodyShort()` and `useEncryptedHeaders()` remain callable on an unvalidated volume. That is defensible (`next()` is the sole route to a header, and `payload()` on a fresh volume yields a zero `LimitedReader`), but a constraint phrased as a general validity guarantee would be a claim broader than its mechanism.

> - **A volume cannot produce a header before its signature is consumed:** `volume.signed`, set only by `readSignature` and checked at the head of `next()`, above the `v.err` arm. `nextVolume` publishes before validating so that `Reader.Close` can reach a stalled signature read, which means `r.vol` is briefly positioned at byte 0; without the flag a reader reaching it would skip nothing (`body.N` is 0) and parse a block header out of the signature bytes. `TestUnvalidatedVolumeRefusesToProduceAHeader` pins it.

- [ ] **Step 5: Verify the claims**

Re-read each sentence written above and confirm the mechanism named actually does what the sentence says. Specifically: confirm `signed` is written in exactly one place and read in exactly one place (`grep -n 'signed' volume.go`), and that the guard sits above the `v.err` check.

- [ ] **Step 6: Quality gate and commit**

```bash
goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
git add reader.go volume.go CLAUDE.md discard_payload_test.go volume_damage_test.go splice_test.go reader_encryption_test.go volume_test.go
git commit -m "docs(rarengine): correct what Close reaches during volume acquisition"
```

---

## Inconclusive / Deferred items

1. **`Reset` runs on the traversal goroutine — so only TWO of the three callers are pinned.** The premise audit derived `Reset`'s leak rather than running it, and `nextVolume`'s new `isClosed`-free path re-reads `r.done` through `publishVolume` rather than the `done` captured at `takeVolume`, which is safe only under that same unstated contract. CLAUDE.md states it; nothing enforces it.
   - *Probe:* after Task 2, attempt a `Reset`-path variant of Task 3's test. If it cannot be constructed without a concurrent `Reset`, the claim is about a caller contract rather than a mechanism.
   - *Expected branches:* (a) it pins cleanly → add it as a further task; (b) it needs concurrency the library forbids → record in the PR body that `Reset` coverage is **by contract, not by test**.
   - **Whichever branch is taken, the PR body must not repeat issue #74's "one fix covers all three callers" as though three are pinned.** `NextEntry` (Task 2) and `Entry.Read` (Task 3) are pinned by mutation-verified tests; `Reset` is not. That sentence is true about the *mechanism* and false about the *evidence*, which is exactly the shape of claim this project has shipped before and had to correct.
   - **The `Reset` exposure that actually grew is the opposite of the obvious one.** `publishVolume` already re-read `r.done` freshly under `volMu` before this plan (`reader.go:878`), and the window between `takeVolume`'s capture and that re-read *shrinks* under the reorder, because the signature read used to sit inside it. What grows is that `r.vol` is now reachable **for the whole duration of the signature read**, so a concurrent `Reset` — which the contract forbids — would `closeCurrentVolume` a volume mid-read. Same contract governs both; name this one, not the window that got smaller.

2. **Whether a stream's `Close` reliably terminates an in-flight `io.ReadFull` for every class that matters.** `stalledVolume` models the cooperative case by construction. A stream whose `Close` does not interrupt its `Read` stays stuck, which is the documented limit — but the plan asserts the fix "rescues well-behaved streams" without testing a second class.
   - *Probe:* add a fixture whose `Close` does NOT release `Read` and assert the traversal stays blocked, documenting the limit as behaviour.
   - *Expected branches:* (a) it confirms the limit → a one-test addition worth having; (b) `synctest` reports it as a bubble deadlock and the test cannot express "correctly still stuck" → drop it and state the limit in prose only.

3. ~~**`openNextVolume`'s retry interaction.**~~ **RESOLVED before implementation.** The full suite, including `volume_damage_test.go`'s empty- and truncated-volume cases, was run against Tasks 1+2 applied in a scratch copy: green under `-race`. Damage behaviour is unchanged by the reorder. Branch (a).

4. ~~**The `unused` linter's treatment of a production function called only from tests.**~~ **RESOLVED before implementation.** `golangci-lint run ./...` was run against the end-of-**Task-4** state — `openVolume` with test callers only, *and* `signed` and `errVolumeNotValidated` both present: **0 issues**. Branch (a), and the stronger statement: the new field and sentinel raise no `unused`/`unparam` finding either. Task 5 is optional and independently rejectable, and the task order stands.

5. **Allocation behaviour, stated narrowly.** The claim under test is only that **allocs/op on the acquisition path is unchanged**. Two things this probe cannot establish, both of which an earlier draft implied it could:
   - The `signed` field's ~8 bytes of struct padding is **below the noise floor** of the decompress benchmarks, whose allocations run to thousands of bytes per op. The probe measures allocation *count*, not `volume`'s size.
   - The failure path *does* now allocate where it did not: under the old ordering `openVolume` returned before constructing a `volume` on a signature failure, so every empty or truncated volume `openNextVolume` skips now costs one `volume` (with its `sync.Once`). One per skipped volume, never per byte.
   - *Probe:* `go test -bench=. -benchmem -count=10 ./...` against `main`, compared with `benchstat`. Every benchmark iteration performs exactly one volume acquisition (`reader_benchmark_test.go:33-41` — `Reset` then `NextEntry`), so the changed path is provably reached.
   - *Expected branches:* (a) allocs/op unchanged → state **that** in the PR body, scoped to the acquisition path, and do not write "allocations unchanged" unqualified; (b) changed → investigate before Gate 3.
   - **This probe cannot falsify the regression it names.** The benchmarks reach only the *success* path, where the `volume` allocation was always present; the one added allocation is on the *skipped-volume* path, which no benchmark exercises. Branch (a) is therefore true by construction and is evidence about the success path only. Either say exactly that, or measure the real thing with `testing.AllocsPerRun` over an acquisition that skips a truncated volume. Reporting (a) as though it covered the named regression would be the same claim-broader-than-its-mechanism error this plan has already corrected twice.

6. **Whether `signed` belongs on `volume` or is better expressed by making `next()` unreachable on an unvalidated volume through the type system** (e.g. a distinct `unvalidatedVolume` type that exposes only `readSignature`).
   - *Probe:* sketch the two-type version and count the call sites that would need to change.
   - *Expected branches:* (a) it is a small change → raise it at review as a follow-up issue, not mid-implementation; (b) it ripples through `r.vol`'s type → record as rejected with the reason, since `r.vol` is read in eight places.

---

## Carried-forward constraints

| # | Constraint | Source | Verified |
|---|---|---|---|
| 1 | The public API surface must not grow | CLAUDE.md | `errVolumeNotValidated`, `newVolume`, `readSignature`, `signed` all unexported — confirmed by round-2 review; no task adds an exported symbol |
| 2 | `volume.Close` is idempotent via `closeOnce` | `volume.go:224` | read in this session |
| 3 | `Close` no longer writes `r.vol` | `reader.go:980`, #72 | read in this session |
| 4 | `r.vol` is assigned only in `takeVolume`/`publishVolume` | `reader.go:848` | `grep -nE '^\s+r\.vol = '` |
| 5 | Every traversal-side `r.vol` read is on the traversal goroutine | `splice.go:76,102,158,237`; `reader.go:298,371,389,567` | enumerated in this session |
| 6 | `openNextVolume` retries on `io.ErrUnexpectedEOF` and sets `r.damaged` | `reader.go:1026` | read in this session |
| 6b | `io.ReadFull` yields `io.ErrUnexpectedEOF` only when `n > 0 && err == io.EOF`; a stream closed before its first byte returns its own error | `io.ReadAtLeast` | **measured** across `os.ErrClosed`, `io.ErrClosedPipe`, `net.Conn`, `os.File` — none satisfies `errors.Is(err, io.ErrUnexpectedEOF)` |
| 6c | `Reset` clears `r.damaged` | `reader.go:175` | read in this session |
| 6d | `golangci-lint` reports 0 issues with `openVolume` called only from tests | `.golangci.yml` | **measured** in a scratch copy at the end-of-Task-2 state |
| 7 | `io.Closer` leaves a second `Close` undefined | Go stdlib doc | cited |
| 8 | All 9 test volume constructions go through `openVolume`; none builds `&volume{}` | `grep 'volume{' *.go` → one site, `volume.go:101` | measured in this session |
| 9 | `synctest` bubbles require channels constructed inside the bubble | `reader_close_test.go:28` | read in this session |
| 10 | A caller's cancellation must never be recorded as the archive's fault | CLAUDE.md, #72's splice finding | Pre-existing: `NextEntry`'s translation (`reader.go:242`) and `latchArchive`'s exemption (`reader.go:350`). **This plan adds no mechanism for it** — a draft that did was measured unobservable. |
| 11 | `sanitizePath`, the rar-bomb guard, and the `historyLen()` bound are untouched by this plan | CLAUDE.md | no task modifies `header.go`, `window.go`, or `dispatch` |

🤖 Generated with [Claude Code](https://claude.com/claude-code)
