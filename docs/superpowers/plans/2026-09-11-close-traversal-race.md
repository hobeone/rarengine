# Reader.Close vs Traversal Race — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Reader.Close()` genuinely safe to call from another goroutine during `NextEntry()` or `Entry.Read()`, which it is documented to be and is not.

**Architecture:** Give `r.vol` exactly one writing goroutine instead of synchronising two. `Close` stops writing `r.vol`; every remaining write moves into two accessors that hold `volMu`; `volume.Close` becomes a `sync.Once` around `rc.Close()` and mutates nothing. What the deleted `v.body` zeroing used to guarantee — that an `Entry` the caller still holds stops producing content — comes from the `done` channel this type already has, handed to each `Entry` the way `context.Context` hands out `Done()`.

**Tech Stack:** Go 1.27.1, `sync.Once`, `go test -race`.

**Spec:** No separate spec — this is the `bounded` route. The settled direction is issue #71's `<!-- work3:gate1-settled -->` comment **as corrected after plan-review rounds 1–4**; the evidence it rests on is the premise-check and three-candidate comments above it on the same issue.

---

## The three design decisions this plan turns on

Each was reached by correcting an earlier draft, and each correction came from more than one reviewer or from reading how the standard library solves the same problem.

### 1. Guard the entrance, but *classify* at the exit

An earlier draft put a cancellation check at the head of `multiVolumePayloadReader.Read`, reasoning that the splicer is the bottom of every decode chain. It is the bottom of every chain and it is the wrong layer, because **a decode chain buffers above it** — constraint 5. Moving the check up to `Entry.Read` closes that. But a head-of-call check **cannot** be what makes the contract true, and a second draft claimed it was: a `Close` landing after the check and during `e.src.Read` still reaches the caller's now-closed stream, and the member's verdict becomes whatever that stream said.

So the rule is split. Four mechanisms, two jobs:

| | mechanism | what it buys | pinned by |
|---|---|---|---|
| **Entrance** | `NextEntry`'s pre-check | A sequential `Close`-then-`NextEntry` performs **no read** on the caller's stream | `TestClosedReaderReadsNothingFromItsVolume` |
| **Entrance** | `Entry.Read`'s head guard | A sequential `Close`-then-`Read` delivers **no bytes** — without it the member completes with a nil error and a passing CRC (constraint 1) | `TestCloseCancelsAnInFlightEntry` |
| **Exit** | `NextEntry`'s translation | The scan's verdict is `ErrReaderClosed` whatever the interleaving | `TestCloseDuringTraversalIsRaceFree` |
| **Exit** | `Entry.finish`'s override | A member's verdict is `ErrReaderClosed` even when the traversal, not the caller, recorded it — `severActive` after `Reset` is the reachable case | `TestRetainedEntrySurvivesCloseThenReset` |

**This is the standard library's shape, not an invention.** `io.Pipe` guards the entrance with a `select`/`default` on its `done` channel at the head of `pipe.read`, and `os.File.wrapErr` classifies at the exit — `if err == poll.ErrFileClosing { err = ErrClosed }` — turning the internal "you closed this" into the caller-facing sentinel on the way out. Under `checkWrapErr`, `os` *panics* if one ever escapes untranslated.

**None of the four is redundant** (constraint 18). **There is deliberately no per-iteration check inside `nextEntry`'s loop** — unreachable by any sequential test, and it changed no verdict once the exit translation existed (constraint 16).

**The two exit gates use deliberately different predicates.** `Entry.finish` overrides only a *short* member, so a CRC mismatch — which can only happen once every declared byte arrived — is never hidden behind a cancellation. `NextEntry` translates *any* scan error. A **member's** verdict may still be read after `Close`, so it must stay true about the bytes delivered; **`NextEntry`'s** verdict decides whether traversal continues, and a closed Reader does not continue. An exclusion list on the `NextEntry` side would be a per-site obligation that drifts — see `handleNonFileBlock`.

### 2. The `done` channel is the only cancellation state

`Reader` has no `closed` field. The channel it already owns is the signal, and `Entry` receives it as `<-chan struct{}`.

Two earlier drafts added a boolean beside `done` — first a value `atomic.Bool`, then a `*atomic.Bool` that `Reset` replaced. The second was measured **unobservable**: a reviewer changed it back to clearing in place and the whole suite stayed green, because `Reset` calls `severActive()` first and that finalizes the only entry that could be affected. It cost one allocation per `NewReader`/`Reset`, a `sync/atomic` import in six files, a sixteen-line comment, and a CLAUDE.md claim that was false.

Reading the standard library settles it (constraint 23):

- **`io.Pipe`** carries `done chan struct{}` and *no* boolean; the reason lives separately in `rerr`/`werr`.
- **`context.cancelCtx`** carries `done` (a channel) plus `err`, and no boolean.
- **A nil done channel meaning "never cancelled" is documented Go**, not a hazard: `Done may return nil if this context can never be canceled`, and `emptyCtx.Done()` returns nil. So `nil` is the correct thing for an `Entry` with no `Reader` behind it — `terminalEntry`'s refusals and the hand-built entries in the tests — rather than a footgun needing a guard.

Because `Reset` **replaces** `r.done` rather than reusing it, an `Entry` retained across a `Close`/`Reset` pair keeps the *closed* channel of its own archive and cannot be un-cancelled. That is structural here in a way it was not for the boolean: the `Entry` captured a value, not a reference to a mutable cell. It also removes the statement-ordering dependency inside `Reset` that the boolean drafts needed.

**One deliberate divergence from `io.Pipe`:** it closes `done` inside a `sync.Once`; this type closes it under `volMu` with a `select`/`default` instead. A pipe is never reset; `Reset` replaces `done`, and CLAUDE.md already records why a `sync.Once` here would be copied out from under a `Close` already inside its `Do`, letting a second body run and close an already-closed channel.

### 3. What this change does NOT deliver

A closed `Reader` may still perform reads on the caller's stream: a `Close` landing between `nextEntry`'s loop and `volume.next()` reaches it. Constraint 15 carries the measurement. **Preventing that would require a lock per read, which this library refuses** — it is the caller-`io.ReadCloser` dependence `Close`'s doc comment already states, and for an `*os.File` the read returns `os.ErrClosed`, which the exit classification then translates.

So the contract is: **no data race, no nil dereference, and a verdict that always names the caller's cancellation.** It is *not* "a closed Reader touches nothing". Task 6 writes the narrower claim into CLAUDE.md.

**Measured figures belong to the constraints table and nowhere else.** A number nobody re-measures goes stale in every copy at once; permanent documents carry the *claim*, the plan and the commit message carry the *provenance*.

---

## Global Constraints

Copied verbatim from `CLAUDE.md`; every task's requirements implicitly include these.

- Quality gate before every commit, all five must pass: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...`
- **Exception, stated because it otherwise reads as a violation:** Tasks 1 and 2 commit a deliberately failing test, which is what TDD's red step *is*. The gate applies from Task 3 onward. No task may commit a red suite for any other reason.
- "Do not introduce heap allocations inside `NextEntry()` or `Entry.Read()` without a benchmark justifying the regression." One thing needs that benchmark: `volume` grows by 32 bytes and `openVolume` runs inside `NextEntry`. See constraint 19 and Task 4 Step 9.
- "Never reintroduce a zeroing loop on the window history buffer."
- The public API surface is compiler-enforced and must not grow. `go doc` must list exactly: `NewReader`, `Reset`, `NextEntry`, `SetPasswords`, `Close`, `Entry.Read`/`Close`/`Header`, `FileHeader`, `FileHeader.Mode`, `VerifyPassword`, `VolumeNumber`, and the error sentinels. **Nothing new may be exported.**
- "making that safe would mean a lock per read on a library whose point is that there is none" — no lock may be taken per byte or per `Read` call. A `select`/`default` on a captured channel is not a lock; `Entry` never touches a `Reader` field.
- The 32-bit job runs the suite under `GOARCH=386`. Nothing here is width-dependent, but the suite must be run under `GOARCH=386 go test -count=1 ./...` before the final commit.
- **Never use bare `git stash` in this worktree** — the stash stack is shared with the main checkout and other sessions.

---

## File Structure

| File | Responsibility after this change |
|---|---|
| `reader.go` | Gains `chanClosed`, `doneChan`, `isClosed`. `NextEntry` translates a scan error while closed. `latchArchive` exempts `ErrReaderClosed`. `Close` no longer writes `r.vol`. `r.vol =` appears in exactly two new accessors, `takeVolume`/`publishVolume`, with `closeCurrentVolume` over the first serving four call sites. Four doc comments corrected. |
| `entry.go` | `Entry` gains `cancelled <-chan struct{}`. Checked at the head of `Read` and applied as a verdict override in `finish`. `newEntry` and `terminalEntry` each gain a parameter. |
| `volume.go` | `volume` gains `closeOnce sync.Once` and `closeErr error`. `Close` closes the stream once and mutates nothing. `next()`'s now-dead `rc == nil` guard is deleted. |
| `splice.go` | One `r.vol` write becomes `r.closeCurrentVolume()`. Nothing else. |
| `reader_close_test.go` | Gains the racing test (extended in Task 4), the cancellation-contract test, the sequential no-reads test, the retained-entry test, and one new fixture. |
| `volume_test.go` | `TestVolumeNextAfterCloseReturnsError` retired, with the reason recorded. |
| `CLAUDE.md` | Concurrency paragraph, "Reset discards an archive" paragraph, and one new invariant. |

---

### Task 1: Add the failing race test

**Files:** Modify `reader_close_test.go` (append)

**Interfaces:**
- Consumes: `rar5Archive`, `rar5Member`, `memberSpec`, `volumesOf` from `testbuild_test.go`.
- Produces: `TestCloseDuringTraversalIsRaceFree`, **extended in Task 4 Step 6** — not joined by a sibling. `-race` instruments the whole binary regardless of what a test asserts, so a second racing test over the same fixture would be a strict superset of this one with 35 duplicated lines.

- [ ] **Step 1: Add the two missing imports**

`reader_close_test.go` currently imports `bytes`, `context`, `errors`, `io`, `sync`, `testing`, `testing/synctest`. The test below also needs `"fmt"` and `"strings"`. Run `goimports -w .` rather than hand-editing the block.

- [ ] **Step 2: Write the failing test**

```go
// Close concurrent with an active traversal must be race-free and must not
// panic. This is the contract Reader.Close's doc comment states outright.
//
// Task 4 extends this test to assert the VERDICT as well; at this point
// ErrReaderClosed is not yet what a cancelled traversal reports, so there is
// nothing to assert but race-freedom.
//
// The `started` channel is load-bearing, not decoration. Without it this test
// passed 6 runs out of 6 at -count=1: Close reaches NextEntry's own closed
// check before the traversal goroutine is scheduled past it, so NextEntry
// returns early and never touches r.vol at all, and the race the test exists
// to catch is never armed. Handing off after the first NextEntry has returned
// puts Close inside the scan rather than in front of it, which reproduced the
// race on 3 runs out of 3.
//
// Still loops: the window between nextEntry's nil check on r.vol and
// dispatch's r.vol.payload() is narrow even once the handoff lands. Without
// -race this same shape produced nil-pointer panics at roughly 9 per 400
// iterations.
func TestCloseDuringTraversalIsRaceFree(t *testing.T) {
	members := make([][]byte, 0, 8)
	for i := range 8 {
		members = append(members, rar5Member(t, memberSpec{
			name:    fmt.Sprintf("m%d.bin", i),
			content: strings.Repeat("payload bytes ", 64),
			withCRC: true,
		}))
	}
	stream := rar5Archive(t, false, members...)

	for range 200 {
		r := NewReader(volumesOf(stream))

		started := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			first := true
			for {
				e, err := r.NextEntry()
				if first {
					close(started)
					first = false
				}
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, e)
				_ = e.Close()
			}
		})

		<-started
		_ = r.Close()
		wg.Wait()
	}
}
```

`wg.Go` rather than `wg.Add(1)` + `go func(){ defer wg.Done() }()`: Go 1.25 added it and `reader_close_test.go:341` already uses it.

- [ ] **Step 3: Run it — it must FAIL on HEAD**

Run: `go test -race -count=1 -run TestCloseDuringTraversalIsRaceFree ./...`

Expected: FAIL with `WARNING: DATA RACE`. Observed on HEAD by a reviewer running this exact test: `volume.go:199` (`volume.Close`) against `splice.go:29` and `volume.go:156`, and `reader.go:777` (`r.vol = nil`) against `reader.go:296`/`:314`.

**If it passes, do not raise the iteration count.** A test that only goes red at 1000 cumulative iterations is a CI flake, which is worse than no test. Check the handoff instead — `started` must be closed *after* the first `NextEntry` returns.

- [ ] **Step 4: Commit**

```bash
git add reader_close_test.go
git commit -m "test(rarengine): add a failing race test for Close during traversal"
```

---

### Task 2: Pin the cancellation contract

One test, not two. An earlier draft split these two assertions about one event across two tests with identical fixtures.

Partly red on HEAD, deliberately: the byte-count assertion passes — `volume.Close`'s `v.body` zeroing already stops delivery on a single-volume archive — and the verdict assertion fails.

**Files:** Modify `reader_close_test.go` (append)

**Interfaces:**
- Consumes: same builders as Task 1, plus `mockReadCloser` (`reader_test.go:14`) by way of `volumesOf`.
- Produces: `TestCloseCancelsAnInFlightEntry`, which Task 4 Step 8 uses to pin `Entry.Read`'s entrance guard.

- [ ] **Step 1: Write the test**

```go
// Close must cancel an Entry that is already in flight, and must say that it
// was cancelled.
//
// A single-volume archive on purpose. Every other Close test uses a member
// waiting for a continuation, which is blocked in the volume receive and
// therefore released by the done channel. Nothing covered the case where the
// bytes are simply THERE and Close has to stop them being delivered -- which
// is why a candidate fix that removed volume.Close's body-zeroing without a
// replacement passed the whole suite while turning cancellation into a full,
// CRC-clean delivery of the member.
//
// mockReadCloser's Close does nothing, which is the point: a caller's
// io.ReadCloser is not required to make an in-flight Read fail, so the refusal
// has to come from this library. This is also what makes the test a precise
// pin on Entry.Read's ENTRANCE guard: with that guard deleted, the member
// completes with a nil error and a passing CRC.
//
// ErrReaderClosed rather than ErrTruncatedFile, which is what HEAD reports:
// "the archive ended before the file's declared size was produced" names the
// archive as the cause of something the caller did.
func TestCloseCancelsAnInFlightEntry(t *testing.T) {
	stream := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "a.bin", content: "HELLOHELLOHELLOHELLO", withCRC: true,
	}))

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	got, readErr := io.ReadAll(e)
	if len(got) != 0 {
		t.Fatalf("ReadAll after Close returned %d bytes (%q); a cancelled "+
			"read must not deliver the member's content", len(got), got)
	}
	if !errors.Is(readErr, ErrReaderClosed) {
		t.Fatalf("ReadAll after Close = %v, want ErrReaderClosed", readErr)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrReaderClosed) {
		t.Fatalf("Entry.Close after Reader.Close = %v, want ErrReaderClosed; "+
			"the verdict must be durable", closeErr)
	}
}
```

- [ ] **Step 2: Run it — the byte count must PASS, the verdict must FAIL**

Run: `go test -race -count=1 -run TestCloseCancelsAnInFlightEntry ./...`

Expected: FAIL at the `want ErrReaderClosed` line, with the exact HEAD text confirmed by a reviewer: `rarengine: archive ended before the file's declared size was produced: file "a.bin": got 0 of 20 bytes`.

If it fails at the **byte-count** line instead, stop: the fixture is not producing the state this plan assumes.

- [ ] **Step 3: Commit**

```bash
git add reader_close_test.go
git commit -m "test(rarengine): pin that Close cancels an in-flight Entry by name"
```

---

### Task 3: One signal, guarded at the entrance and classified at the exit

The `done` channel becomes the only cancellation state and is handed to each `Entry` — see design decision 2. **No boolean is introduced.**

**Files:**
- Modify: `reader.go` — three new helpers, `Close`, `NextEntry`, `latchArchive`, `dispatch`, `nextVolume`
- Modify: `entry.go` — struct, `newEntry`, `terminalEntry`, `Read`, `finish`
- Modify: `decoder50_test.go`, `entry_test.go`, `splice_test.go`, `skip_damaged_test.go` — the constructor call sites. **No new imports needed in any of them**: the added argument is `nil`.

**Interfaces:**
- Produces: `chanClosed(<-chan struct{}) bool`; `(*Reader).doneChan() <-chan struct{}`; `(*Reader).isClosed() bool`; `Entry.cancelled <-chan struct{}`; `newEntry(fh *FileHeader, src io.Reader, cancelled <-chan struct{}) *Entry`; `terminalEntry(fh *FileHeader, cause error, cancelled <-chan struct{}) *Entry`.

- [ ] **Step 1: Add the three helpers**

In `reader.go`, next to `Close`:

```go
// chanClosed reports whether ch has been closed, without receiving from it.
//
// The shape is io.Pipe's (src/io/pipe.go, pipe.read): a select with a default
// is how the standard library asks a done channel whether cancellation has
// happened. A nil ch is never ready and so reports false -- which is
// context.Context's documented meaning for a nil Done channel, "this can never
// be cancelled", and is exactly right for an Entry with no Reader behind it.
func chanClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// doneChan returns the done channel in force, under the lock.
//
// Under the lock because Reset REPLACES r.done; this is the only way the field
// is read outside a critical section that already holds volMu, so there is no
// unsynchronised read of it anywhere. Called once per NextEntry and once per
// admitted member -- never per byte, which is the cost profile volMu already
// has.
func (r *Reader) doneChan() <-chan struct{} {
	r.volMu.Lock()
	done := r.done
	r.volMu.Unlock()
	return done
}

// isClosed reports whether Close has been called on the archive in force.
func (r *Reader) isClosed() bool { return chanClosed(r.doneChan()) }
```

- [ ] **Step 2: Delete `Reader.closed`, and close the channel under the lock**

**Delete the field.** `reader.go:58` (`closed bool`) and its comment go, and so does `Reset`'s `r.closed = false` (`reader.go:155`). This step is written out because the plan's design decision 2 and Task 6's CLAUDE.md invariant both assert "there is no `closed` flag" — and a reviewer following the other steps literally left the field in place with one write and no read. `go build`, `go vet` and `golangci-lint` all pass in that state, so nothing would catch the invariant being committed alongside the field it denies.

Then `Close`:

```go
	r.volMu.Lock()
	// Idempotent without a sync.Once, deliberately. io.Pipe uses one; a pipe
	// is never reset, and Reset REPLACES this field, so a Once would be copied
	// out from under a Close already inside its Do -- see volMu's comment.
	if !chanClosed(r.done) {
		close(r.done)
	}
	v := r.vol
	volumes := r.volumes
	r.volMu.Unlock()
```

`Reset` needs nothing else: `r.done = make(chan struct{})` under `volMu` is now the whole of "revive a closed Reader".

**Mechanical check, run it now:** `grep -n 'closed bool\|r\.closed' reader.go` must return nothing.

- [ ] **Step 3: The entrance guard and the exit translation in `NextEntry`**

```go
	// Checked before r.fatal and before any read, so a sequential
	// Close-then-NextEntry performs no read on the caller's stream at all.
	// A Close landing DURING this call is not caught here -- nothing at the
	// head of a call can be -- it is caught by the translation below.
	if r.isClosed() {
		return nil, ErrReaderClosed
	}
	if r.fatal != nil {
		return nil, r.fatal
	}
	e, err := r.nextEntry()
	if err != nil {
		// A Close that landed mid-scan. nextEntry's loop had already passed
		// the pre-check, so r.vol.next() went on to read a stream the caller
		// had closed underneath it, and err is whatever that stream said --
		// os.ErrClosed for an *os.File, which is what this library's consumers
		// actually feed. Reporting it would name the caller's own decision as
		// an archive failure AND latch it onto r.fatal for the Reader's life.
		//
		// This is os.File.wrapErr's move: translate the internal
		// "you closed this" into the caller-facing sentinel at the boundary.
		//
		// Unconditional, unlike Entry.finish's override, which fires only for
		// a SHORT member. A member's verdict may still be read after Close, so
		// it must stay true about the bytes delivered; this verdict only
		// decides whether traversal continues, and a closed Reader does not.
		//
		// A guard at the head of the scan loop was tried instead and removed:
		// unreachable by any sequential test, and it changed no verdict once
		// this translation existed. See constraint 16.
		if r.isClosed() {
			return nil, ErrReaderClosed
		}
		return nil, r.latchArchive(err)
	}
```

- [ ] **Step 4: Exempt `ErrReaderClosed` from the latch**

`nextVolumePayload` (`splice.go`) calls `latchArchive` directly and can reach one through `openNextVolume`:

```go
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrNoNextVolume) &&
		!errors.Is(err, ErrReaderClosed) {
		r.fatal = err
	}
```

and extend the doc comment's "deliberately never latched" paragraph:

```go
// ErrReaderClosed is likewise never latched, for a different reason:
// r.fatal exists to stop traversal resuming past an unresolved ARCHIVE
// failure, and a closed Reader is not an archive failure at all. Nothing
// observes the latch either way -- NextEntry's closed pre-check runs before
// its r.fatal check, and Reset clears both -- but leaving it out is what lets
// r.fatal be described as archive-level without an exception. Load-bearing in
// one direction: if that pre-check ever moves below the r.fatal check, the
// latch surfaces.
```

- [ ] **Step 5: Give `Entry` the channel**

In `entry.go`, add to the `Entry` struct after `done error`:

```go
	// cancelled is the done channel of the archive this member belongs to,
	// closed by Reader.Close. This is context.Context's Done() shape, and a
	// nil channel carries context's documented meaning: never ready, so this
	// member has no Reader that can cancel it. That is true of terminalEntry's
	// refusals and of the hand-built entries in the tests, so nil needs no
	// guard and is not a footgun.
	//
	// A <-chan struct{} rather than a *Reader: reader.go builds entries and
	// entry.go knows nothing about traversal, so a back-pointer would invert
	// that to read one signal.
	//
	// Captured once at construction and never re-read from the Reader, which
	// is what makes the verdict durable: Reset REPLACES Reader.done, so a
	// member the caller retained across a Close/Reset pair still holds the
	// CLOSED channel of its own archive and cannot be un-cancelled by the next
	// archive starting. A boolean beside the channel could not do that without
	// an ordering rule inside Reset.
	//
	// Checked at THIS layer rather than lower because the chain buffers.
	// decoder50.Read serves from its outbuf and then from the window, touching
	// its source only when Available() hits zero, so a compressed member can
	// hold up to half the window in decoded plaintext below Entry.Read and
	// above everything else. A check under that buffer keeps delivering real
	// content with nil errors until it drains.
	cancelled <-chan struct{}
```

Both constructors take it:

```go
func newEntry(fh *FileHeader, src io.Reader, cancelled <-chan struct{}) *Entry {
	return &Entry{
		Header:    fh,
		cur:       fh,
		src:       src,
		size:      fh.UnpackedSize,
		remaining: fh.UnpackedSize,
		cancelled: cancelled,
	}
}

func terminalEntry(fh *FileHeader, cause error, cancelled <-chan struct{}) *Entry {
	return &Entry{Header: fh, cur: fh, done: cause, cancelled: cancelled}
}
```

A parameter rather than a field assignment at the call site: a second call site that forgot the assignment would be silently uncancellable, and the compiler will not let it forget.

- [ ] **Step 6: Guard the entrance in `Entry.Read`**

Placement is load-bearing. It goes **below** the `e.remaining <= 0` arm, not directly after the `e.done` guard:

```go
	if e.done != nil {
		return 0, e.done
	}
	if e.src == nil {
		return 0, ErrNoActiveFile
	}
	if e.remaining <= 0 {
		return 0, e.finish(nil)
	}
	// The caller closed the Reader. This is the ENTRANCE guard, and it is the
	// only thing standing between a sequential cancellation and full, clean
	// delivery of the member: without it the read reaches a source that is
	// still serving (a caller's ReadCloser need not fail after Close), the
	// member meets its declared size, and finish reports success with a
	// passing CRC. finish's override does NOT cover this -- there is no error
	// for it to reclassify. See constraint 1.
	//
	// BELOW the remaining <= 0 arm, and that is the whole of why this block is
	// not three lines higher. finish's override is gated on short() precisely
	// so a member that produced every byte it declared is never blamed on a
	// cancellation -- and passing ErrReaderClosed in from HERE routes around
	// that gate, because finish takes it as the incoming err rather than as
	// something to reclassify. Above the arm, a zero-length member -- an empty
	// file, or any directory -- reported "reader is closed" after a Close it
	// had already completed before, reachable through the documented
	// context.AfterFunc pattern plus a deferred Entry.Close. Below it, a
	// member with nothing left to produce completes cleanly and only a member
	// still owed bytes is cancelled, which is the same rule finish applies.
	//
	// After the e.done guard so a verdict already recorded is not overwritten.
	if chanClosed(e.cancelled) {
		return 0, e.finish(ErrReaderClosed)
	}
	if len(p) == 0 {
		return 0, nil
	}
```

Pinned by `TestZeroLengthMemberIsCleanEvenWithAnUncheckableDigest`'s neighbour — add to `reader_close_test.go`:

```go
// A member with nothing left to produce completes cleanly, even after Close.
//
// Entry.Read's guard sits below the remaining <= 0 arm for this reason: a
// zero-length member -- an empty file, or any directory -- has already
// produced everything it declared, so a later Close cancels nothing. Reporting
// ErrReaderClosed there would be the same false accusation finish's short()
// gate exists to prevent, arriving by the one path that bypasses it.
func TestZeroLengthMemberIsNotCancelledByALaterClose(t *testing.T) {
	stream := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "empty.bin", content: "", withCRC: true,
	}))

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	if verdict := e.Close(); verdict != nil {
		t.Fatalf("zero-length Entry.Close after Reader.Close = %v, want nil; "+
			"a member that produced everything it declared was not cancelled",
			verdict)
	}
}
```

- [ ] **Step 7: Classify at the exit in `Entry.finish`**

```go
	if err == nil {
		err = e.verifyChecksum()
	}
	// A member that ran SHORT while its archive's Reader was closed ran short
	// because the caller closed it. Whatever the stream said on the way out --
	// os.ErrClosed, a bare EOF read as truncation, or the splicer's "volume
	// ended inside its payload", all true of a closed volume -- names the
	// archive for the caller's own decision.
	//
	// The reachable case is severActive, which stamps truncated() on an Entry
	// the caller still holds when Reset follows Close -- the documented
	// context.AfterFunc pattern -- and which Read's entrance guard never sees
	// because severActive reads nothing. TestRetainedEntrySurvivesCloseThenReset
	// pins exactly that; a reviewer measured that no other path reaches this
	// branch with an error it actually changes.
	//
	// Gated on short(), not on err != nil alone. A CRC mismatch or a LastBlock
	// contradiction happens only once every declared byte has been produced,
	// so it cannot have been caused by a cancellation, and hiding it behind
	// ErrReaderClosed would be the false-verdict failure in reverse.
	//
	// err != nil is redundant against every CURRENT call site -- finish(nil)
	// is only ever reached when !short() -- and stays as the backstop against
	// a future call site that breaks that invariant, where dropping it would
	// silently turn a real success into ErrReaderClosed.
	if err != nil && e.short() && chanClosed(e.cancelled) {
		err = ErrReaderClosed
	}
	if err == nil {
		err = io.EOF
	}
```

- [ ] **Step 8: Fix the call sites**

`reader.go:483`: `e := newEntry(fh, nil)` → `e := newEntry(fh, nil, r.doneChan())`.

`terminalEntry` in `reader.go` at `:419`, `:457`, `:473`, `:477`, `:488` — each gains `, r.doneChan()`.

Test sites gain `, nil` — "this entry has no Reader that can cancel it", which is both true and idiomatic: `decoder50_test.go:149`, `entry_test.go:13`, `entry_test.go:105` (`terminalEntry`), `entry_test.go:222`, `splice_test.go:322`, `skip_damaged_test.go:669`. No new imports.

`entry_test.go:216`'s comment says "via `newEntry(fh, nil)`" and now names a two-argument signature that no longer exists. Correct it in the same edit — a comment quoting a call shape is a paired artifact, and this is the moment it drifts.

- [ ] **Step 9: Run the tests**

Run: `go test -race -count=1 -run TestCloseCancelsAnInFlightEntry ./...` — PASS.

Run: `go test -race -count=1 -run 'TestReset|TestClose' ./...` — all PASS.

Run: `go test -race -count=1 ./...`
Expected: `TestCloseDuringTraversalIsRaceFree` still FAILS (Task 5 fixes it). Everything else PASSES. If any *other* test fails, stop — see Inconclusive items 1 and 5.

- [ ] **Step 10: Mutation-check what CAN be checked here**

Only two of the four mechanisms have their pinning test in place at this point; **Task 4 Step 8 checks all four in one pass.** Do not treat this as the complete check.

Delete `Entry.Read`'s entrance guard, re-run `go test -race -count=1 ./...`.

Expected: **nothing fails.** ~~An earlier version of this step predicted `TestCloseCancelsAnInFlightEntry` would fail reporting 20 bytes delivered.~~ That measurement was taken on the *fully implemented* tree and is wrong here: `volume.Close` still zeroes `v.body` until Task 4, so delivery is stopped anyway, the member ends short, and `finish`'s override reclassifies the truncation to `ErrReaderClosed`. Two mechanisms overlap at this point in the sequence and neither is independently observable. Both become so in Task 4 Step 8, once the body-zeroing is gone. **Restore the guard.**

The general rule this taught, worth applying to the rest of the plan: **a mutation measured on the final tree is not necessarily reproducible mid-sequence.** Task 4 Step 8's table was measured with every task applied and is valid there; this step transcribed one of its rows into a position where a since-removed mechanism still masks it.

Delete the `e.short() && chanClosed(e.cancelled)` override from `finish`, re-run.
Expected: **nothing fails yet.** A reviewer measured the branch firing 108–122 times per 400 racing iterations and being a no-op every time, because `Entry.Read`'s guard already passed `ErrReaderClosed` in. Its one reachable productive path is `Close`→`Reset`→retained `Entry`, which Task 4 Step 7 tests. **Restore it** and proceed.

- [ ] **Step 11: Commit**

```bash
git add reader.go entry.go reader_close_test.go decoder50_test.go entry_test.go \
	splice_test.go skip_damaged_test.go
git commit -m "feat(rarengine): name cancellation as the cause, at both choke points"
```

`reader_close_test.go` is in the list because Step 6 adds `TestZeroLengthMemberIsNotCancelledByALaterClose` to it; an earlier version of this line omitted the file and would have left that test uncommitted.

---

### Task 4: volume.Close stops mutating the volume

**Files:**
- Modify: `volume.go` — struct, `Close`, `next`
- Modify: `volume_test.go` — retire one test
- Modify: `reader_close_test.go` — one new fixture, two new tests, one extended test

**Interfaces:**
- Consumes: everything Task 3 produced — together they are what now provides the guarantee this task's deleted lines used to provide.
- Produces: an immutable `v.rc`, which Task 5 depends on.

- [ ] **Step 0: Capture the benchmark baseline BEFORE editing**

This is the task with the allocation regression. An earlier draft benchmarked Task 3 alone and so structurally could not see it.

```bash
go test -bench='Decompress_Store|Decompress_Compress|Decompress_Solid|ReaderResetReusesWindow' \
	-benchmem -count=10 ./... > "$SCRATCH/bench-before.txt"
```

A **fixed** `-bench` selection, not `-bench=.` — see Step 9 for why.

- [ ] **Step 1: Add the fields**

In `volume.go`, in the `volume` struct, after `err error`:

```go
	// closeOnce makes Close idempotent without mutating rc. The previous
	// idempotency test was `v.rc == nil`, which required Close to nil rc -- a
	// write racing every traversal read of that field, from the one method
	// another goroutine may call. Once, plus an immutable rc, removes the
	// write instead of synchronising it, and absorbs the concurrent double
	// Close that Task 5 makes possible by leaving r.vol non-nil.
	//
	// sync.Once and not an atomic CAS: Once establishes happens-before for
	// every caller, so a second caller's read of closeErr is ordered after the
	// first's write. A CAS would make the flag safe and leave closeErr racy.
	// (Reader.done is closed under volMu rather than by a Once for the
	// opposite reason -- Reset replaces it. A volume is never reset.)
	//
	// These two fields cost 32 bytes per volume -- Step 9 measures it.
	closeOnce sync.Once
	closeErr  error
```

Add `"sync"` to the import block.

- [ ] **Step 2: Rewrite Close**

```go
// Close closes the underlying stream once, and mutates nothing else.
//
// It used to nil v.rc and zero v.body, which is what made Reader.Close racy:
// those are fields the traversal reads and writes, and Reader.Close is the one
// method another goroutine may call. Leaving rc immutable after construction
// means a concurrent Close reads it safely, and leaving body alone means only
// the traversal ever writes it.
//
// What the body-zeroing used to guarantee -- that an Entry the caller still
// holds stops producing content -- is now the Reader's done channel, read
// through Entry.cancelled. That is strictly more than the zeroing covered: the
// zeroing sat below decoder50's window, so a compressed member kept delivering
// buffered plaintext after it.
func (v *volume) Close() error {
	v.closeOnce.Do(func() {
		if v.rc != nil {
			v.closeErr = v.rc.Close()
		}
	})
	return v.closeErr
}
```

- [ ] **Step 3: Delete `next()`'s dead guard**

Delete the `if v.rc == nil` arm at `volume.go:145`.

**The justification is deadness, not unreachability.** An earlier draft argued that no traversal path reaches `next()` after `Close` — measured false (constraint 15). The correct argument holds regardless of scheduling: **`v.rc` is never nil at all.** `openVolume` (`volume.go:86`) is the only `&volume{}` construction site, it never leaves `rc` nil, and after Step 2 `Close` no longer nils it. Reading a *closed* `rc` is the caller-`io.ReadCloser` dependence `Reader.Close`'s doc comment already states — an `os.ErrClosed`, not a panic, and the exit classification translates it.

- [ ] **Step 4: Retire `TestVolumeNextAfterCloseReturnsError`**

Inconclusive item 4 branch (b), taken explicitly. A reviewer confirmed it is the only test that fails otherwise (`volume_test.go:243`).

Delete `volume_test.go:227-244`, and record why above the neighbouring test:

```go
// TestVolumeNextAfterCloseReturnsError was deleted here. It asserted that
// next() after Close() errors rather than dereferencing a nil rc -- a state
// volume.Close created itself, by nilling rc for idempotency. closeOnce
// provides idempotency without the write, so rc is immutable after
// construction and openVolume is the only constructor, which makes the nil it
// guarded unrepresentable rather than merely unreached.
```

- [ ] **Step 5: Add the failing-stream fixture**

`volumesOf` yields `mockReadCloser`, whose `Close` does nothing and which keeps serving bytes. That is right for Task 2 — it proves the refusal comes from this library — and **wrong for the racing test**, whose subject is what happens when a read after `Close` fails. A reviewer measured that with `volumesOf` the `NextEntry` translation fires 5 times per 400 iterations and carries a non-`ErrReaderClosed` error only twice, so deleting the translation left the test green across 4000 iterations. With the fixture below it fires 15–23 times per 400 and the deletion turns the test red.

Confirm the name is free (`grep -rn 'closedStreamVolume' *.go` returns nothing), then append to `reader_close_test.go`:

```go
// closedStreamVolume fails reads after its own Close, the way *os.File does --
// which is what both of this library's consumers actually feed it
// (constraint 9). recordingVolume and mockReadCloser deliberately keep serving
// after Close, which is the right fixture for proving the refusal comes from
// this library; this is the right fixture for proving that a refusal coming
// from the STREAM is translated rather than reported.
type closedStreamVolume struct {
	r      *bytes.Reader
	closed atomic.Bool
}

func (v *closedStreamVolume) Read(p []byte) (int, error) {
	if v.closed.Load() {
		return 0, os.ErrClosed
	}
	return v.r.Read(p)
}

func (v *closedStreamVolume) Close() error {
	v.closed.Store(true)
	return nil
}
```

`atomic.Bool` rather than a plain bool: the fixture is read by the traversal goroutine and closed by the test's, so a plain field would be a data race in the test itself and `-race` would report it against this file rather than the library. Needs `os` and `sync/atomic` in `reader_close_test.go` only.

- [ ] **Step 6: Extend the racing test to assert the verdict**

Do **not** add a second racing test. In `TestCloseDuringTraversalIsRaceFree`, add above the loop:

```go
	// Now that ErrReaderClosed is what a cancelled traversal reports, this
	// test asserts the verdict as well as race-freedom. The fixture changes
	// with it: volumesOf's mockReadCloser keeps serving after Close, so no
	// read ever fails and NextEntry's translation has nothing to translate.
	acceptable := func(err error) bool {
		return errors.Is(err, ErrReaderClosed) || errors.Is(err, io.EOF) ||
			errors.Is(err, ErrNoNextVolume)
	}
```

and replace the loop body:

```go
		vol := &closedStreamVolume{r: bytes.NewReader(stream)}
		volumes := make(chan io.ReadCloser, 1)
		volumes <- vol
		close(volumes)
		r := NewReader(volumes)

		started := make(chan struct{})
		var bad error
		var wg sync.WaitGroup
		wg.Go(func() {
			first := true
			for {
				e, err := r.NextEntry()
				if first {
					close(started)
					first = false
				}
				if err != nil {
					if !acceptable(err) && bad == nil {
						bad = fmt.Errorf("NextEntry: %w", err)
					}
					return
				}
				if _, rerr := io.Copy(io.Discard, e); rerr != nil &&
					!acceptable(rerr) && bad == nil {
					bad = fmt.Errorf("Entry.Read %q: %w", e.Header.Name, rerr)
				}
				if cerr := e.Close(); cerr != nil && !acceptable(cerr) &&
					bad == nil {
					bad = fmt.Errorf("Entry.Close %q: %w", e.Header.Name, cerr)
				}
			}
		})

		<-started
		_ = r.Close()
		wg.Wait()

		if bad != nil {
			t.Fatalf("a cancelled traversal reported a cause that is not the "+
				"caller's own Close: %v", bad)
		}
```

`io.EOF` and `ErrNoNextVolume` are accepted alongside `ErrReaderClosed`: a `Close` landing after the archive has legitimately ended is not a cancellation of anything, and demanding `ErrReaderClosed` there would assert a race outcome rather than a contract.

- [ ] **Step 7: Pin the sequential entrance, and the retained entry**

```go
// A sequential Close-then-read must not touch the volume at all.
//
// This pins the ENTRANCE guards -- NextEntry's pre-check and Entry.Read's --
// and nothing more. It deliberately does NOT claim that a closed Reader never
// reads; a Close landing concurrently does reach the stream, and preventing
// that would need a lock per read.
func TestClosedReaderReadsNothingFromItsVolume(t *testing.T) {
	stream := rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "a.bin", content: "AAAA", withCRC: true}),
		rar5Member(t, memberSpec{name: "b.bin", content: "BBBB", withCRC: true}),
	)

	vol := &recordingVolume{r: bytes.NewReader(stream)}
	volumes := make(chan io.ReadCloser, 1)
	volumes <- vol
	close(volumes)

	r := NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	// Asserted, not assumed, matching TestPackedRemainder_NoReadAfterVolumeClose:
	// if Reader.Close ever stops closing the open volume, "no reads after
	// close" holds trivially and this test stops exercising its own subject.
	if !vol.closed {
		t.Fatal("Reader.Close did not close the open volume")
	}

	if _, err := io.ReadAll(e); !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("ReadAll after Close = %v, want ErrReaderClosed", err)
	}
	if _, err := r.NextEntry(); !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("NextEntry after Close = %v, want ErrReaderClosed", err)
	}
	if vol.readsAfterClose != 0 {
		t.Fatalf("a sequential Close-then-read hit the volume %d times; want 0",
			vol.readsAfterClose)
	}
}

// An Entry retained across Close+Reset keeps reporting the cancellation.
//
// This is the ONLY deterministically reachable path on which Entry.finish's
// override changes a verdict. Reset calls severActive, which stamps
// truncated() on an entry that never reached its declared size -- Entry.Read's
// entrance guard never sees it, because severActive reads nothing -- so
// without the override the caller is told "archive ended before the file's
// declared size was produced" for its own cancellation.
//
// It stays correct with no ordering rule inside Reset, which is what the done
// channel buys over a boolean: the Entry captured the channel of ITS archive,
// and Reset replaces the field rather than reopening the channel, so the
// entry's copy stays closed however Reset's statements are ordered.
//
// Documented pattern, not a contrivance: context.AfterFunc(ctx, r.Close)
// followed by Reset for the next archive is what Reader.Close's own doc
// comment describes, and a deferred Entry.Close is enough to reach it.
func TestRetainedEntrySurvivesCloseThenReset(t *testing.T) {
	stream := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "a.bin", content: "HELLOHELLOHELLOHELLO", withCRC: true,
	}))

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	r.Reset(volumesOf(stream))

	if verdict := e.Close(); !errors.Is(verdict, ErrReaderClosed) {
		t.Fatalf("retained Entry.Close after Close+Reset = %v, want "+
			"ErrReaderClosed", verdict)
	}
}
```

- [ ] **Step 8: Mutation-check all four mechanisms, in one pass**

Delete each in turn, run `go test -race -count=1 ./...`, confirm the named test fails, **restore before the next**:

| delete | expect to fail | measured failure text |
|---|---|---|
| `NextEntry`'s pre-check | `TestClosedReaderReadsNothingFromItsVolume` | `NextEntry after Close = <nil>` — the second `NextEntry` *succeeds* |
| `Entry.Read`'s entrance guard | `TestCloseCancelsAnInFlightEntry` (and the above) | `returned 20 bytes ("HELLOHELLOHELLOHELLO")` |
| `NextEntry`'s translation | `TestCloseDuringTraversalIsRaceFree` | `NextEntry: file already closed` |
| `Entry.finish`'s override | `TestRetainedEntrySurvivesCloseThenReset` | the `ErrTruncatedFile` text |

**If any deletion changes nothing, stop and report it.** An unpinned check is one a later refactor deletes. Three of these four predictions were wrong in an earlier draft — two optimistic, one pessimistic — so they are measurements to reproduce, not reasoning to trust. Note the second row fails two tests, not one.

- [ ] **Step 9: Measure the regression this task introduces**

```bash
go test -bench='Decompress_Store|Decompress_Compress|Decompress_Solid|ReaderResetReusesWindow' \
	-benchmem -count=10 ./... > "$SCRATCH/bench-after.txt"
benchstat "$SCRATCH/bench-before.txt" "$SCRATCH/bench-after.txt"
```

Expected: **+32 B/op on every benchmark, allocation count unchanged**, from `unsafe.Sizeof(volume{})` going 64 → 96. A reviewer bisected this to the `volume` growth alone. `Entry` and `Reader` are unchanged in size by this design — the channel replaces no field and adds one word to `Entry`.

This is the benchmark CLAUDE.md's rule asks for and the justification it must carry: the growth is one `volume` per volume *advance* — not per byte, not per member — and the allocation count does not move, so the archive-level cost is 32 bytes times the number of parts.

**Expect an ns/op cost too, and record it rather than explaining it away.** Two reviewers measured this differently and the second isolated it properly, so the numbers below are the ones to reproduce. On a quiet box (baseline-vs-baseline ≤0.7%, `p=0.618`), HEAD → full plan on the fixed selection:

| benchmark | ns/op |
|---|---|
| `Decompress_Store` | **+7.9%** |
| `Decompress_Compress` | **+5.5%** |
| `Decompress_Solid` | **+2.5%** |
| `ReaderResetReusesWindow` | **+6.3%** |

Bisected: roughly half is `volume`'s 32-byte growth (`Store +4.9%` with *only* `closeOnce`/`closeErr` applied and no test-file changes, so no layout confound), and roughly half is `Entry.Read`'s `chanClosed` (`Store +3.9%`, `Solid +2.4%`, on trees differing by four lines). A `select`/`default` compiles to a `selectnbrecv` runtime call, not the inlined load an `atomic.Bool` would give — that is the price of the single-signal design, and it is a deliberate trade, not a surprise.

**Do not use `-bench=.`.** An earlier reviewer running the full set saw `BenchmarkFilterExecution` — pure assembly, untouched by any task — move −15%, which is binary layout and swamps the real signal. The fixed selection above is what to trust.

If your numbers differ materially from the table, report them; do not proceed on the assumption that a difference is noise.

- [ ] **Step 10: Run**

Run: `go test -race -count=1 ./...` — only `TestCloseDuringTraversalIsRaceFree` fails.
Run: `go test -race -count=5 -run 'TestClosedReaderReadsNothing|TestRetainedEntry|TestCloseCancels' ./...` — PASS.

- [ ] **Step 11: Commit**

```bash
git add volume.go volume_test.go reader_close_test.go
git commit -m "refactor(rarengine): make volume.Close close the stream and mutate nothing"
```

---

### Task 5: Give r.vol one writing goroutine

Three helpers, and `r.vol =` appears in exactly two of them — checkable by `grep -n 'r\.vol = ' reader.go splice.go` returning two lines, rather than by re-enumerating six call sites and hoping. It also removes copies of a block that already exists twice (constraint 13).

**`takeVolume` returns the `done` channel alongside the volume.** `nextVolume` needs both from one acquisition; an earlier draft split its critical section in two and then spent a paragraph arguing the split was harmless.

**Files:**
- Modify: `reader.go` — `Close`, `Reset`, `nextEntry`, `handleNonFileBlock`, `nextVolume`, plus three new methods
- Modify: `splice.go:123-124`

**Interfaces:**
- Consumes: `volume.closeOnce` from Task 4 — without it this task introduces a concurrent double-`Close`.
- Produces: `(*Reader).takeVolume() (*volume, chan struct{})`, `(*Reader).publishVolume(*volume) bool`, `(*Reader).closeCurrentVolume()`.

- [ ] **Step 1: Add the accessors**

```go
// takeVolume removes the open volume from the Reader and returns it together
// with the done channel in force, leaving the caller to close the volume
// outside the lock.
//
// This and publishVolume are the ONLY two functions that assign r.vol. That is
// the invariant, expressed as something grep can check rather than as a rule
// six call sites have to remember: every write is on the traversal goroutine
// and under volMu, so the field has one writing goroutine and Close's read is
// ordered against all of them.
//
// done comes back from the same acquisition because nextVolume needs the pair
// and a second accessor for one channel read would be a third place this lock
// is taken.
func (r *Reader) takeVolume() (*volume, chan struct{}) {
	r.volMu.Lock()
	v, done := r.vol, r.done
	r.vol = nil
	r.volMu.Unlock()
	return v, done
}

// publishVolume attaches v as the open volume, or reports false if the Reader
// was closed first -- in which case v is closed here and never becomes
// reachable.
//
// The re-check is under the same lock Close takes, so only two orderings are
// possible: either Close saw this volume, or this saw Close. The select in
// nextVolume proves nothing on its own -- when both its cases are ready Go
// picks at random, so a Close that landed during acquisition can have taken
// the volumes branch anyway, and by then Close has already read r.vol, drained
// the queue and returned.
func (r *Reader) publishVolume(v *volume) bool {
	r.volMu.Lock()
	if chanClosed(r.done) {
		r.volMu.Unlock()
		// --- no lock held below this line ---
		_ = v.Close()
		return false
	}
	r.vol = v
	r.volMu.Unlock()
	return true
}

// closeCurrentVolume closes the open volume and clears the pointer, for the
// four callers that need no done channel.
//
// All four are spent-volume closes -- once per volume, never per byte, which
// is the cost volMu was always documented to have. Three of them wrote r.vol
// with no lock at all (reader.go twice, splice.go once); the fourth, Reset,
// was already doing exactly this inline.
func (r *Reader) closeCurrentVolume() {
	if v, _ := r.takeVolume(); v != nil {
		_ = v.Close()
	}
}
```

- [ ] **Step 2: Stop Close writing r.vol**

Delete `r.vol = nil` (`reader.go:777`) and annotate the surviving read:

```go
	// Read, never written. This assignment was the second writer of the field,
	// and it is what every unlocked traversal read raced against -- and what
	// made dispatch's r.vol.payload() a reachable nil dereference, observed at
	// 9 panics per 400 iterations without the race detector.
	//
	// Dropping it also drops an accidental ownership handoff: with Close
	// clearing the pointer, whichever goroutine read it first won and the
	// other saw nil, so only one of them called v.Close(). volume.closeOnce is
	// what absorbs that now, which is why Task 4 could not come after this.
	v := r.vol
```

- [ ] **Step 3: Route the five sites through the helpers**

`Reset` (`reader.go:133-140`), `nextEntry` (`reader.go:320-321`), `handleNonFileBlock` (`reader.go:554-555`) and `nextVolumePayload` (`splice.go:123-124`) each replace their inline `_ = r.vol.Close(); r.vol = nil` with `r.closeCurrentVolume()`.

`nextVolume`'s head (`reader.go:843-858`):

```go
	prev, done := r.takeVolume()
	if prev != nil {
		_ = prev.Close()
	}
```

and its tail (`reader.go:893-903`):

```go
	if !r.publishVolume(v) {
		return ErrReaderClosed
	}
	return nil
```

- [ ] **Step 4: Check the invariant mechanically**

Run: `grep -n 'r\.vol = ' reader.go splice.go` — exactly two lines, in `takeVolume` and `publishVolume`.

- [ ] **Step 5: The race test must now PASS**

Run: `go test -race -count=1 -run TestCloseDuringTraversalIsRaceFree ./...` — PASS, no `WARNING: DATA RACE`, and no mis-named verdict from the assertions Task 4 added.

- [ ] **Step 6: Hunt the panic without the race detector**

Run: `go test -count=1 -run TestCloseDuringTraversalIsRaceFree ./...` — PASS. On HEAD this shape panicked at roughly 9 per 400 iterations.

- [ ] **Step 7: Full suite plus 32-bit**

Run: `go test -race -count=1 ./...` — all PASS.
Run: `go test -race -count=10 -run 'TestClose' ./...` — all PASS.
Run: `GOARCH=386 go test -count=1 ./...` — all PASS.

- [ ] **Step 8: Commit**

```bash
git add reader.go splice.go
git commit -m "fix(rarengine): give r.vol one writing goroutine"
```

---

### Task 6: Correct the documents that now say something false

**Every claim below is scoped to what was measured.** Four drafts each wrote something broader than its mechanism delivered — "one check covers all three chains", "both entrances report `ErrReaderClosed`", "a closed Reader performs no reads at all", and a pointer-replacement claim that a reviewer showed was unobservable. Each was caught by a reviewer rather than by a test.

**Files:**
- Modify: `reader.go` — `vol` field comment, `volMu` field comment, `Close` doc comment
- Modify: `CLAUDE.md` — concurrency paragraph, "Reset discards an archive" paragraph, one new invariant

- [ ] **Step 1: `reader.go:21-24` — the `vol` field comment**

```go
	// vol is the open volume, or nil when none is. An advance constructs a new
	// volume rather than repointing one, so a failed advance cannot leave a
	// partially consumed volume reachable -- nextVolume assigns the result.
	//
	// One exception, and it is deliberate: after Close this field keeps
	// pointing at a volume that has been CLOSED, because Close no longer
	// writes it. That is weaker than this codebase's usual preference for
	// unrepresentable over unreachable, and it buys the field a single writing
	// goroutine -- which is what made every unlocked read of it safe and what
	// removed a reachable nil dereference from dispatch. A traversal that
	// reaches the stale pointer reads a closed stream and gets that stream's
	// error, which Entry.finish and NextEntry both translate; it does not
	// panic, and it is not a data race.
	vol *volume
```

- [ ] **Step 2: `reader.go:60-73` — the volMu field comment**

```go
	// volMu orders the fields Close shares with the traversal: r.done,
	// r.volumes, and r.vol -- which Close only READS. Every write of r.vol is
	// on the traversal goroutine and inside takeVolume or publishVolume, so
	// the field has one writer rather than two synchronised ones. Taken at
	// volume transitions only, once per volume and never per byte.
	//
	// r.done is in here because Reset REPLACES it: a plain sync.Once would be
	// copied out from under a Close already inside its Do, letting a second Do
	// body run and close an already-closed channel, which panics. A field
	// replaced under a lock cannot be copied at the wrong moment, so the
	// hazard stops existing rather than being synchronised around. That is
	// also why Close tests the channel with chanClosed under this lock instead
	// of using the sync.Once io.Pipe uses -- a pipe is never reset.
	//
	// It does not make a volume's CONTENTS safe and does not need to: v.rc is
	// immutable after construction and v.body is written only by the
	// traversal, because volume.Close stopped mutating both.
	volMu sync.Mutex
```

- [ ] **Step 3: `reader.go:753-767` — Close's doc comment**

Replace the paragraph beginning "Close does not nil the open volume":

```go
// Close does not nil the open volume and does not touch its fields. It reads
// the pointer under volMu and closes the underlying stream; the traversal
// alone writes r.vol, v.rc is immutable after construction, and v.body is
// written only by the traversal.
//
// An earlier version of this comment claimed the volume's body was zeroed so
// an in-flight read "sees EOF rather than a nil dereference", and the same
// commit assigned r.vol = nil three lines below. Both halves were false: the
// assignment was the nil dereference. The zeroing was also below decoder50's
// window, so it did not stop a compressed member anyway.
//
// What Close guarantees an in-flight reader is a VERDICT, not silence. A
// sequential Close-then-read touches the stream not at all: NextEntry and
// Entry.Read both refuse on the done channel before reading. A Close landing
// concurrently, mid-call, does reach the stream -- refusing that would mean a
// lock per read -- and what it gets back is translated rather than reported:
// Entry.finish overrides a short member's verdict and NextEntry translates the
// scan's, so the caller is told ErrReaderClosed and never os.ErrClosed or
// ErrTruncatedFile. This is os.File.wrapErr's arrangement, which turns
// poll.ErrFileClosing into ErrClosed at the same boundary.
```

Replace the "One limit" paragraph:

```go
// One limit remains, and it is the caller's rather than this library's.
// Unblocking a read that is stalled inside the underlying stream depends on
// that stream's own Close being safe to call while a Read is in flight, and so
// does the mid-call case above. os.File and net.Conn are; a type doing its own
// buffering may not be. This is the same division io.Pipe and net.Conn draw,
// and it is why Close closes the stream rather than trying to interrupt a read
// it does not own.
```

- [ ] **Step 4: `CLAUDE.md` — the concurrency paragraph**

Replace the two sentences from "`volMu` guards the `r.vol` pointer" through "would mean a lock per read." with:

```markdown
`volMu` orders `r.done`, `r.volumes` and `r.vol` — the last of which `Close` only reads. Every `r.vol` write is on the traversal goroutine, inside `takeVolume` or `publishVolume`, so the pointer has one writer rather than two synchronised ones; the lock is taken at volume transitions, never per byte. A volume's contents need no lock because nothing shares them: `volume.Close` closes the stream and mutates nothing, leaving `v.rc` immutable after construction and `v.body` written only by the traversal. Cancelling an `Entry` the caller still holds goes through the `done` channel itself, handed to each `Entry` the way `context.Context` hands out `Done()` — there is no second "closed" flag to keep in step with it.
```

- [ ] **Step 5: `CLAUDE.md` — the "Reset discards an archive" paragraph**

Replace the final sentence with:

```markdown
`severActive` covers both cases by nilling `e.src`; the claim that `volume.Close`'s body-zeroing covered the single-volume case was true only of `Reader.Close`, which has no `severActive`, and never of `Reset`, which calls it first. `Reader.Close` now stops an in-flight member through the `done` channel instead, and the body-zeroing is gone. Because `Reset` replaces that channel rather than reopening it, an `Entry` the caller retained across a `Close`/`Reset` pair still holds its own archive's closed channel and reports the cancellation — with no ordering rule inside `Reset` for a future editor to violate.
```

- [ ] **Step 6: `CLAUDE.md` — add the new invariant**

```markdown
- **Cancellation is one channel, checked above the decode chain and classified where every outcome already passes.** There is no `closed` flag: `Reader.done` is the whole of it, closed by `Close` under `volMu` and handed to each `Entry` as a `<-chan struct{}` — `context.Context`'s `Done()` arrangement, including its meaning for nil, which is "this can never be cancelled" and is exactly right for a `terminalEntry` or a hand-built test entry. Two drafts carried a boolean beside the channel; the second was measured **unobservable**, and a boolean is what would have needed a statement-ordering rule inside `Reset` to keep a retained `Entry` cancelled. Because `Reset` replaces the channel, an `Entry` that captured it stays cancelled by construction. Four mechanisms read it, doing two jobs. The *entrance* guards — `NextEntry`'s pre-check and `Entry.Read`'s — make a sequential `Close`-then-read touch the caller's stream not at all; `Entry.Read`'s in particular is the only thing between a cancelled read and **full, CRC-clean delivery of the member**, because a caller's `io.ReadCloser` is not required to fail a `Read` after `Close` and the chain will simply keep serving. The *exit* classification — `Entry.finish` overriding a short member's verdict, `NextEntry` translating its scan's error — is what makes the contract true under any interleaving, because a guard at the head of a call can be outrun by a concurrent `Close` while a choke point on the way out cannot; this is `os.File.wrapErr`'s move, which rewrites `poll.ErrFileClosing` to `ErrClosed` at the same boundary and panics under `checkWrapErr` if one escapes. The two exit gates differ deliberately: a member's verdict may still be read after `Close`, so `finish` overrides only a **short** member and never hides a CRC mismatch, which can only arise once every declared byte has been produced; `NextEntry`'s verdict only decides whether traversal continues. The entrance guard's layer is why it is not lower: the mechanism it replaces — `volume.Close` zeroing the aliased `io.LimitedReader` — sat below `decoder50`'s window, which `decoder50.Read` serves from without touching its source, so a compressed member could hold up to half the window in decoded plaintext that a bottom-of-chain check never saw. **What this does NOT claim, because it was measured false:** a closed `Reader` may still perform reads on the caller's stream, through the window between `nextEntry`'s loop and `volume.next()`. Stopping that would mean a lock per read, which this library refuses; the guarantee is that no such read is a data race, none can dereference nil, and none reaches the caller as the archive's fault. Each of the four mechanisms has exactly one test that fails when it alone is deleted — `TestClosedReaderReadsNothingFromItsVolume`, `TestCloseCancelsAnInFlightEntry`, `TestCloseDuringTraversalIsRaceFree`, `TestRetainedEntrySurvivesCloseThenReset` — and that mapping is the point: three of the four were mispredicted before they were measured.
```

- [ ] **Step 7: Measure HEAD against the finished branch**

Task 4's benchmark brackets Task 4 alone, so it cannot see Task 3's per-`Read` cost — which is roughly half the total on `Decompress_Store` and all of it on `Decompress_Solid`. An earlier draft bracketed Task 3 alone and had the mirror-image blind spot; measuring one task in isolation twice is not the same as measuring the change.

```bash
git stash list   # confirm nothing of yours is here; do NOT stash
git worktree add "$SCRATCH/head-bench" main
cd "$SCRATCH/head-bench" && go test \
	-bench='Decompress_Store|Decompress_Compress|Decompress_Solid|ReaderResetReusesWindow' \
	-benchmem -count=10 ./... > "$SCRATCH/bench-head.txt"
```

then the same selection on this branch, and `benchstat "$SCRATCH/bench-head.txt" "$SCRATCH/bench-final.txt"`.

Expected: `+32 B/op`, allocations unchanged, and the ns/op figures in Task 4 Step 9's table. **Record the result in the PR body**, whatever it is — this is the number a future reader will want when they ask what the race fix cost, and it is the one thing in this plan that no test will preserve.

- [ ] **Step 8: Full gate and commit**

Run: `goimports -w . && go fix ./... && go vet ./... && go test -race ./... && golangci-lint run ./...` — all pass, `0 issues`.

Run: `go doc -all . | grep -E "^(func|type) "` and confirm the surface is unchanged from `main`.

```bash
git add reader.go CLAUDE.md
git commit -m "docs(rarengine): describe the concurrency model that now exists"
```

---

## Inconclusive / Deferred items

**1. No existing test asserts `ErrTruncatedFile` for a cancelled read.**
*Probe:* `grep -rn "ErrTruncatedFile" *_test.go`, then run the cancellation tests after Task 3 Step 9.
*Expected branches:* (a) none for a `Close` path → proceed; (b) one does → decide whether the new verdict is better, and update that test with the reason in its comment rather than silently.

**2. `NextEntry`'s SECOND `r.fatal` check is not covered by the exit translation.**
Task 3 Step 3 guards only the `err != nil` branch. On the success path `NextEntry` then does `if r.fatal != nil { return nil, r.fatal }`. If `nextVolumePayload` latches a stream-level error during `finishActive`'s solid drain and the scan afterwards *succeeds*, that raw error is returned untranslated. A reviewer instrumented this check to panic when it fires while closed and ran 200 non-solid plus 2000 solid racing iterations under `-race`: it never fired. Branch (a) is supported but not proven by inspection.
*Probe:* re-run that instrumentation after Task 3, or settle it by reading `finishActive` and `nextVolumePayload`.
*Expected branches:* (a) cannot carry a cancellation-caused error → record why; (b) it can → extend the translation to the second check.

**3. `Entry.Read`'s entrance guard does not break `finishActive`'s solid-abandon drain.**
`finishActive` decodes an abandoned member's remainder through `Entry.Read`; after `Close` that drain now returns immediately, leaving the window marked incomplete. A reviewer saw `TestSolid*` green.
*Probe:* `go test -race -run 'TestSolid' ./...` after Task 3.
*Expected branches:* (a) green, window incomplete → correct: a closed archive has no successor to protect; (b) red → `finishActive` needs its own entrance.

**4. `Reset` fully revives a cancelled Reader.**
The revival is now one statement — replacing `r.done` — where two drafts had two.
*Probe:* `go test -race -run 'TestReset' ./...` after Task 3.
*Expected branches:* (a) green; (b) red → the latch exemption is the likely cause, since it changes what survives on `r.fatal`.

**5. Nothing constructs an `Entry` or a `volume` outside their constructors.**
A stray `&Entry{}` would have a nil `cancelled` — legal, meaning "never cancelled", and therefore **silently uncancellable**, which is the one place this design is weaker than a pointer that would panic. A reviewer confirmed `&Entry{}` appears only at `entry.go:50`/`:67` and `&volume{}` only at `volume.go:86`.
*Probe:* `grep -rn '&Entry{\|&volume{' *.go` after Task 3.
*Expected branches:* (a) constructors only → the compiler-required parameter is sufficient; (b) another exists → give it the channel, and consider whether the constructors should be the only way to build either type.

**6. Deferred — `r.volumes` is read unlocked while `Reset` writes it.**
`reader.go:867` (`case rc, ok = <-r.volumes`) against `reader.go:157`. A `Reset`-vs-traversal race, not a `Close` one, and out of scope. Note this design removes the equivalent hazard for `r.done` by routing every read through `doneChan()`, which makes `r.volumes` the last field of its kind.
*Probe:* a test racing `Reset` against a traversal blocked in `nextVolume`.
*Action:* file a separate issue; do not fix in this PR.

---

## Carried-forward constraints

Facts established before this plan existed, from the premise audit, the adversarial design review, and plan-review rounds 1–4. Rows 11–23 are measured or read from source, not argued.

| # | Constraint | Established by |
|---|---|---|
| 1 | Removing `volume.Close`'s `v.body = io.LimitedReader{}` **without a replacement** converts cancellation into delivery of the member's full content with a nil error and a passing CRC. Measured: `""`+`ErrTruncatedFile` on HEAD vs `"HELLOHELLOHELLOHELLO"`+`nil` without it. | Adversarial review, four-variant experiment |
| 2 | Deleting `r.vol = nil` from `Reader.Close` **without** `sync.Once` in `volume.Close` is *strictly worse than HEAD* for `volume.rc`. | Adversarial review, `only13` variant |
| 3 | `r.vol` is written **unlocked** at exactly three sites: `reader.go:321`, `:555`, `splice.go:124`. All other writes are already under `volMu`. | `grep`, confirmed by two reviewers |
| 4 | `splice_test.go:322` constructs `&multiVolumePayloadReader{r: nil, ...}`. This plan does not touch the splicer's `Read`, so the fixture needs only the extra argument to `newEntry`. | Reviewer; verified directly |
| 5 | **`decoder50.Read` buffers above the splicer** — serves from `outbuf`, then the window, calling `fill` only when `Available() == 0`, and `fill` runs `for win.Available() < win.size/2`. A bottom-of-chain check can be bypassed by up to half the window in decoded plaintext. | `altitude` and soundness independently, round 1; verified against `decoder50.go:460-487` |
| 6 | `Reader.Close` never calls `severActive`; `Reset` does. This is why the body-zeroing was load-bearing for `Close` and already dead for `Reset` — and why `severActive` stamps `truncated()` on a cancelled member unless `finish` classifies it. | Reviewer; verified against `reader.go` |
| 7 | `TestVolumeNextAfterCloseReturnsError` (`volume_test.go:227-244`) is the single existing test that fails if `v.rc` stops being nilled. | Reviewer, round 1; re-confirmed on an implemented tree, round 4 |
| 8 | CLAUDE.md's claim that `volume.Close` "covers the single-volume case by zeroing the aliased body" is already historical for `Reset`. | Reviewer |
| 9 | Both gonzbd consumers feed a raw `*os.File`, which *is* safe for concurrent Read/Close. A mid-call read after `Close` returns `os.ErrClosed` — which is why `closedStreamVolume`, not `mockReadCloser`, is the racing test's fixture. | Direct check of the gonzbd source |
| 10 | `r.volumes` is read unlocked at `reader.go:867` while `Reset` writes it under `volMu`. Pre-existing, out of scope. | Reviewer |
| 11 | **A race test without a handoff channel does not go red** — 6/6 green at `-count=1`; red 3/3 with a `started` channel closed after the first `NextEntry` returns. | Soundness, round 1 |
| 12 | **After deleting `r.vol = nil`, an unguarded `nextEntry` reaches `r.vol.next()` on a closed volume**, and the caller's stream error is latched onto `r.fatal` for the Reader's life. Fixed by the exit translation plus the latch exemption. | `altitude` and soundness independently, round 1 |
| 13 | `reader.go:133-140` (`Reset`) and `:848-858` (`nextVolume`) already contain the take-and-close block verbatim. | `reuse` lens, round 1 |
| 14 | **Two read-tracking test fixtures already exist** and a third named `countingReadCloser` does not compile: `countingReadCloser` (`reader_abandon_test.go:11`, counts bytes) and `recordingVolume` (`packed_drain_test.go:100`, counts reads **after** `Close`). | `reuse` and soundness independently, round 2 |
| 15 | **A closed `Reader` DOES read from the caller's stream**, through the window between `nextEntry`'s loop and `volume.next()`: **12, 17 and 5 reads** after the stream's own `Close` returned, across three 400-iteration runs. **This is the one place these figures are recorded.** | Soundness, round 2 |
| 16 | **A loop-top guard in `nextEntry` is unpinnable** — `NextEntry`'s pre-check returns first; deleting it left the suite green and the race test passing at `-count=5`. | Soundness, round 2 |
| 17 | The `ErrReaderClosed` latch exemption changes nothing observable but is what lets `r.fatal` be described as archive-level without an exception. Load-bearing in one direction: if the pre-check moves below the `r.fatal` check, the latch surfaces. | `simplification` and soundness independently, round 2 |
| 18 | **None of the four cancellation mechanisms is redundant.** Dropping `NextEntry`'s pre-check makes a second `NextEntry` read the closed volume; dropping `Entry.Read`'s guard delivers the member's full content with a nil error; dropping either exit mechanism mis-names a verdict. | `simplification`, round 3 |
| 19 | **`volume` grows 64 → 96 bytes** from `closeOnce`+`closeErr`: **+32 B/op on every benchmark, allocation count unchanged**, bisected to the `volume` growth alone. `openVolume` runs inside `NextEntry`, so the benchmark belongs in Task 4. | Soundness, rounds 3 and 4, measured |
| 20 | **`Entry.finish`'s override is a no-op on every racing path** — 108–122 firings per 400 iterations, always with `err` already `ErrReaderClosed`. Its one reachable productive path is `Close`→`Reset`→retained `Entry`. | Soundness, round 3 |
| 21 | **`mockReadCloser` cannot pin `NextEntry`'s translation** — it keeps serving after `Close`, so deleting the translation left the test green across 4000 iterations. With a stream returning `os.ErrClosed` the translation fires 15–23 times per 400 and the deletion turns it red. | Soundness, round 3 |
| 22 | **`-bench=.` is unusable for this change**: `BenchmarkFilterExecution`, pure assembly untouched by any task, moves **−15%** on binary layout alone and swamps the signal. Always benchmark a fixed selection. Round 4 concluded from a narrow re-run that there was *no* decode delta; round 5 re-measured on a quiet box and found a real one — see row 24. The layout warning stands; the "it was all noise" conclusion does not. | Soundness rounds 4 and 5; round 5 supersedes |
| 24 | **The change costs decode latency, and it is bisected.** HEAD → full plan on the fixed selection at `-count=10`, baseline-vs-baseline ≤0.7%: `Decompress_Store` **+7.9%**, `Compress` **+5.5%**, `Solid` **+2.5%**, `ReaderReset` **+6.3%**, all `p=0.000`. Roughly half is `volume`'s 32-byte growth (`Store +4.9%` in isolation, no test-file changes); roughly half is `Entry.Read`'s `chanClosed` (`Store +3.9%`, `Solid +2.4%`, trees differing by four lines) — a `select`/`default` is a `selectnbrecv` call where an `atomic.Bool` would inline to a load. | Soundness, round 5, isolated |
| 25 | **`Entry.Read`'s guard must sit BELOW the `remaining <= 0` arm.** Above it, a zero-length member — an empty file or any directory — reports `ErrReaderClosed` after a `Close` it had already completed before, reachable through the documented `context.AfterFunc` pattern plus a deferred `Entry.Close`. Passing `ErrReaderClosed` in as `err` routes around `finish`'s `short()` gate, which exists precisely to stop a member that produced every declared byte being blamed on a cancellation. | Soundness, round 5, measured and fix verified |
| 23 | **The standard library carries one cancellation signal, not a signal plus a flag.** `io.Pipe`: `done chan struct{}` closed inside a `sync.Once`, guarded by `select`/`default` at the head of `pipe.read`, reason in `rerr`/`werr`. `context.cancelCtx`: `done` plus `err`, no boolean. `context.Context.Done()` documents `Done may return nil if this context can never be canceled`, and `emptyCtx.Done()` returns nil — so nil-means-never-cancelled is idiomatic. `os.File.wrapErr` classifies at the exit: `if err == poll.ErrFileClosing { err = ErrClosed }`, panicking under `checkWrapErr` if one escapes. | Read from Go 1.27.1 `src/io/pipe.go`, `src/context/context.go`, `src/os/file.go` |
