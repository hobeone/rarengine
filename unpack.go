package rarengine

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// UnpackOptions configures the high-level archive extraction process.
type UnpackOptions struct {
	Password         string
	Logger           *slog.Logger
	OneFolder        bool
	OverwriteFiles   bool
	IgnoreUnrarDates bool
	OnEntry          func(header *FileHeader)
}

// ErrUnusableName reports a member whose archive-internal name is left empty
// by sanitizePath -- ".." or "/", say. The member cannot be written anywhere
// safe, so it is recorded as damaged rather than extracted.
var ErrUnusableName = errors.New("rarengine: member name is unusable after sanitizing")

// UnpackResult reports what an extraction produced. Damage is a result rather
// than an error: one member a RAR archive cannot deliver says nothing about
// the members behind it, and in a non-solid archive those are independently
// readable. Returning only an error forced the caller to discard them.
//
// A non-nil error from UnpackDir is archive-level -- the volumes could not be
// opened, or the stream stopped being parseable. The result is still returned
// alongside it, so an abort partway through reports what it managed first.
type UnpackResult struct {
	// Files holds the absolute path of every member written to disk.
	Files []string

	// Damaged holds one entry per member that could not be delivered. Empty
	// on a clean archive. A caller reporting success without consulting it
	// is claiming more than the extraction proved.
	Damaged []DamagedEntry
}

// DamagedEntry identifies one member that could not be extracted, and why.
// Nothing was left on disk for it: a partially written file is removed before
// the entry is recorded, because a truncated file is indistinguishable from a
// complete one once extraction has finished.
type DamagedEntry struct {
	// Header is the failed member's header, carried over from FileError.
	// Never nil -- an error that cannot name its member is not damage this
	// type can describe, and stays an archive-level error instead.
	Header *FileHeader

	// Err is the underlying cause: ErrTruncatedFile, ErrCRCMismatch,
	// ErrNoNextVolume, ErrRarBombDetected, ErrUnusableName, or whichever
	// sentinel the decode failed with. Match it with errors.Is.
	//
	// ErrChecksumUnsupported is reported here too, and means something
	// weaker than the others: the member decoded without complaint, but it
	// carries a key-derived MAC this library cannot check, so nothing
	// confirms the bytes are right. It is listed as damage because an
	// unverifiable member is not a verified one.
	Err error
}

// asDamaged reports whether err is a per-member failure that leaves the stream
// standing on the next block header, and converts it if so.
//
// The *FileError type is the whole test. It is constructed in exactly one
// place, gated on proof that the failed member's packed remainder was read
// down to zero, so its presence -- and nothing else about the error -- is what
// makes continuing to the next member safe. Widening this to any other error
// would resume parsing at an offset the block structure does not describe.
func asDamaged(err error) (DamagedEntry, bool) {
	fe, ok := errors.AsType[*FileError](err)
	if !ok || fe.Header == nil {
		return DamagedEntry{}, false
	}
	return DamagedEntry{Header: fe.Header, Err: fe.Err}, true
}

type volumeInfo struct {
	path  string
	index int
}

// SortVolumes takes a slice of volume file paths, parses their internal main
// archive headers to extract the volume number, and returns the sorted paths
// in ascending order.
func SortVolumes(paths []string) ([]string, error) {
	var vols []volumeInfo
	var parseFailed bool

	for _, p := range paths {
		if idx, ok := getClassicVolumeIndex(p); ok {
			vols = append(vols, volumeInfo{
				path:  p,
				index: idx,
			})
			continue
		}

		f, err := os.Open(p) // #nosec G304
		if err != nil {
			parseFailed = true
			break
		}

		volIdx, err := readVolumeIndex(f)
		_ = f.Close()
		if err != nil {
			parseFailed = true
			break
		}

		vols = append(vols, volumeInfo{
			path:  p,
			index: volIdx,
		})
	}

	if parseFailed {
		sorted := append([]string(nil), paths...)
		slices.Sort(sorted)
		return sorted, nil
	}

	slices.SortFunc(vols, func(a, b volumeInfo) int {
		return cmp.Compare(a.index, b.index)
	})

	sorted := make([]string, len(vols))
	for i, v := range vols {
		sorted[i] = v.path
	}
	return sorted, nil
}

func getClassicVolumeIndex(path string) (int, bool) {
	if strings.Contains(strings.ToLower(path), ".part") {
		return -1, false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".rar" {
		return 0, true
	}
	if len(ext) == 4 && ext[1] == 'r' && ext[2] >= '0' && ext[2] <= '9' && ext[3] >= '0' && ext[3] <= '9' {
		var idx int
		_, _ = fmt.Sscanf(ext[2:], "%d", &idx)
		return idx + 1, true
	}
	return -1, false
}

func readVolumeIndex(r io.Reader) (int, error) {
	version, err := detectVersion(r)
	if err != nil {
		return 0, err
	}

	var h *BlockHeader
	switch version {
	case VersionRAR5:
		h, err = ReadBlockHeader(r)
	case VersionRAR3:
		h, err = ReadRAR3BlockHeader(r)
	default:
		return 0, fmt.Errorf("unsupported RAR version: %v", version)
	}

	if err != nil {
		return 0, err
	}

	if version == VersionRAR5 {
		ah, err := ParseArchiveHeader(h)
		if err != nil {
			return 0, err
		}
		if ah.VolumeNumber < 0 {
			return 0, nil
		}
		return ah.VolumeNumber, nil
	} else {
		if h.Type != 0x73 {
			return 0, errors.New("invalid archive header type")
		}
		return 0, nil
	}
}

// setupSandbox prepares the target output directory and opens a sandboxed os.Root jail.
func setupSandbox(outputDir string) (*os.Root, string, error) {
	// Resolve canonical absolute outputDir path (handles symlinks safely)
	absOutputDir, err := filepath.EvalSymlinks(outputDir)
	if err != nil {
		absOutputDir, err = filepath.Abs(outputDir)
		if err != nil {
			return nil, "", fmt.Errorf("rarengine: resolve output path: %w", err)
		}
	}

	if err := os.MkdirAll(absOutputDir, 0755); err != nil { // #nosec G301
		return nil, "", fmt.Errorf("rarengine: create output dir: %w", err)
	}

	root, err := os.OpenRoot(absOutputDir)
	if err != nil {
		return nil, "", fmt.Errorf("rarengine: sandbox output dir: %w", err)
	}
	return root, absOutputDir, nil
}

// openVolumeChannel opens volume file handles sequentially and pushes them to a buffered channel.
func openVolumeChannel(sortedVols []string) (chan io.ReadCloser, error) {
	volumesChan := make(chan io.ReadCloser, len(sortedVols))
	for _, volPath := range sortedVols {
		vf, err := os.Open(volPath) // #nosec G304
		if err != nil {
			close(volumesChan)
			for v := range volumesChan {
				_ = v.Close()
			}
			return nil, fmt.Errorf("rarengine: open volume %s: %w", volPath, err)
		}
		volumesChan <- vf
	}
	close(volumesChan)
	return volumesChan, nil
}

// writeCounter records the first error the underlying writer reported.
//
// io.Copy cannot say whether a failure came from its reader or its writer, and
// the two mean opposite things here: a read failure is the archive's problem
// and costs one member, a write failure is the output filesystem's and costs
// every member behind it. Reporting ENOSPC as archive damage told the caller
// their download was corrupt.
type writeCounter struct {
	w   io.Writer
	err error
}

func (wc *writeCounter) Write(p []byte) (int, error) {
	n, err := wc.w.Write(p)
	if err != nil && wc.err == nil {
		wc.err = err
	}
	return n, err
}

// createTemp opens the file a member is written into before it is renamed
// into place.
//
// The suffix is random, and a name already taken is never reclaimed by
// removing it. Both matter because the archive chooses member names: a
// derivable suffix is a name the archive can also contain, and the earlier
// version removed the colliding file, so an archive holding both "a.bin" and
// "a.bin.rarengine-part" destroyed the extraction of the second and still
// listed it in Files -- the same defect the temporary name exists to prevent,
// through a door the archive picks.
func createTemp(root *os.Root, destRel string) (string, *os.File, error) {
	var buf [8]byte
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", nil, fmt.Errorf("rarengine: temporary name for %s: %w", destRel, err)
		}
		tmpRel := destRel + ".rarengine-part-" + hex.EncodeToString(buf[:])

		out, err := root.OpenFile(tmpRel, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		switch {
		case err == nil:
			return tmpRel, out, nil
		case errors.Is(err, os.ErrExist):
			continue // taken by a member of this archive; pick another
		default:
			return "", nil, fmt.Errorf("rarengine: create file %s: %w", tmpRel, err)
		}
	}
	return "", nil, fmt.Errorf("rarengine: no free temporary name for %s", destRel)
}

// extractEntry writes one member into the sandboxed root.
//
// It reports a decode failure separately from a filesystem failure, because
// only the first is survivable: a bad member costs that member, a bad output
// directory costs the archive. A *FileError is never available here -- it is
// built in endFile, which only Next drives -- so a failing read returns the
// bare cause and the caller supplies the header.
//
// The member is written to a temporary name and renamed into place only once
// it has decoded completely, so a destination path never holds a member that
// failed. Writing to the destination directly meant a failure left a truncated
// file behind that looked extracted, and under OverwriteFiles it destroyed a
// good copy already on disk before it knew the member was bad.
func extractEntry(ctx context.Context, root *os.Root, sd *StreamDecompressor, header *FileHeader, opts UnpackOptions, absOutputDir string, logger *slog.Logger) (path string, streamErr error, err error) {
	var destRel string
	if opts.OneFolder {
		destRel = filepath.Base(header.Name)
	} else {
		destRel = header.Name
	}

	if opts.OneFolder && !opts.OverwriteFiles {
		destRel = uniquePath(root, destRel)
	}

	// Convert slashes to host-native separators for relative path (needed for Windows)
	destRel = filepath.FromSlash(destRel)

	// sanitizePath drops "." and ".." components, so a member named ".." or
	// "/" arrives here as the empty string. That is the guard working, not a
	// broken archive -- but it costs this one member, not the extraction: an
	// unusable name used to reach OpenFile and come back as a fatal error,
	// so a single odd name discarded every member behind it.
	// A NUL byte survives sanitizePath and reaches the filesystem calls,
	// which reject it -- as a fatal error, so one such name would cost every
	// member behind it. It is this member's loss, like any other name that
	// cannot be written.
	if destRel == "" || destRel == "." || strings.ContainsRune(destRel, 0) {
		return "", fmt.Errorf("%w: %q", ErrUnusableName, header.Name), nil
	}

	logger.Info("rarengine: extracting entry", "name", header.Name, "target_rel", destRel, "size", header.UnpackedSize, "is_dir", header.IsDir)

	if header.IsDir {
		if !opts.OneFolder {
			if err := root.MkdirAll(destRel, 0750); err != nil {
				return "", nil, fmt.Errorf("rarengine: mkdir %s: %w", destRel, err)
			}
		}
		return "", nil, nil
	}

	if !opts.OverwriteFiles {
		if _, statErr := root.Stat(destRel); statErr == nil {
			logger.Info("rarengine: skipping existing file", "path", destRel)
			return "", nil, nil
		}
	}

	if opts.OnEntry != nil {
		opts.OnEntry(header)
	}

	if err := root.MkdirAll(filepath.Dir(destRel), 0750); err != nil {
		return "", nil, fmt.Errorf("rarengine: mkdir parent %s: %w", filepath.Dir(destRel), err)
	}

	tmpRel, out, err := createTemp(root, destRel)
	if err != nil {
		return "", nil, err
	}

	dropPartial := func() {
		if rmErr := root.Remove(tmpRel); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			logger.Warn("rarengine: could not remove partial file", "path", tmpRel, "err", rmErr)
		}
	}

	wc := &writeCounter{w: out}
	n, copyErr := io.Copy(wc, &contextReader{ctx: ctx, r: sd})
	closeErr := out.Close()

	switch {
	case copyErr != nil:
		dropPartial()
		// Cancellation is not damage -- the member may have been perfectly
		// intact and the caller simply stopped. Tested against the error
		// actually returned rather than against ctx.Err() independently,
		// because a deadline expiring after a genuine ErrCRCMismatch would
		// otherwise discard the real cause and report cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(copyErr, ctxErr) {
			return "", nil, ctxErr
		}
		if wc.err != nil {
			return "", nil, fmt.Errorf("rarengine: write file %s: %w", tmpRel, wc.err)
		}
		return "", copyErr, nil
	case closeErr != nil:
		dropPartial()
		return "", nil, fmt.Errorf("rarengine: close file %s: %w", tmpRel, closeErr)
	}

	mode := header.Mode() & 0666
	if mode != 0 && header.HostOS != 0 {
		_ = root.Chmod(tmpRel, mode)
	}

	if !opts.IgnoreUnrarDates && !header.ModificationTime.IsZero() {
		_ = root.Chtimes(tmpRel, header.ModificationTime, header.ModificationTime)
	}

	if err := root.Rename(tmpRel, destRel); err != nil {
		dropPartial()
		return "", nil, fmt.Errorf("rarengine: rename %s: %w", tmpRel, err)
	}

	absPath := filepath.Join(absOutputDir, destRel)
	logger.Info("rarengine: extracted entry complete", "name", header.Name, "written_bytes", n)
	return absPath, nil, nil
}

// UnpackDir extracts a RAR archive sequentially from the first volume path
// into the output directory.
//
// A member that cannot be delivered does not stop the extraction. It is
// recorded in UnpackResult.Damaged and traversal continues, because in a
// non-solid archive the members behind it are independently readable. That
// covers a member which ended short, failed its checksum, tripped the rar-bomb
// guard, or whose name is unusable once sanitized. Nothing is written to disk
// for any of them: a member is written under a temporary name and renamed into
// place only once it has decoded completely.
//
// Two things still end the traversal, and both return the result accumulated
// up to that point alongside the error:
//
// A solid archive cannot be resumed. Its members back-reference their
// predecessors' decoded bytes, so once one is damaged the rest cannot be
// reconstructed, and they are refused with ErrSolidStreamBroken.
//
// A member whose header does not parse is refused before there is a header to
// name it with, so it cannot be reported as a damaged member and is returned
// as the error instead. The payload is still dropped, so this is a reporting
// limit rather than a stream-alignment one.
func UnpackDir(ctx context.Context, firstVolumePath string, outputDir string, opts UnpackOptions) (UnpackResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if err := ctx.Err(); err != nil {
		return UnpackResult{}, err
	}

	logger.Info("rarengine: starting volume discovery", "first_volume", firstVolumePath)
	vols, err := discoverVolumes(firstVolumePath)
	if err != nil {
		return UnpackResult{}, fmt.Errorf("rarengine: discover volumes: %w", err)
	}
	logger.Info("rarengine: discovered volumes", "count", len(vols), "paths", vols)

	logger.Info("rarengine: sorting volumes by internal headers")
	sortedVols, err := SortVolumes(vols)
	if err != nil {
		return UnpackResult{}, fmt.Errorf("rarengine: sort volumes: %w", err)
	}
	logger.Info("rarengine: sorted volumes order", "paths", sortedVols)

	root, absOutputDir, err := setupSandbox(outputDir)
	if err != nil {
		return UnpackResult{}, err
	}
	defer func() { _ = root.Close() }()

	volumesChan, err := openVolumeChannel(sortedVols)
	if err != nil {
		return UnpackResult{}, err
	}

	sd := NewStreamDecompressor(volumesChan)
	if opts.Password != "" {
		sd.SetPassword(opts.Password)
	}

	var res UnpackResult

	// recorded tracks whether the member currently in progress has already
	// been added to res.Damaged by the read site below, so that the FileError
	// Next reports for that same member is not counted twice.
	recorded := false

	// unread names a member this loop accepted but never read -- a directory
	// entry, or a file skipped because it already existed. Next drains those
	// on the caller's behalf, and that drain can fail. Without the header
	// held here there is nothing to attribute the failure to, and a member
	// lost that way was reported in neither Files nor Damaged.
	var unread *FileHeader

	// Every exit below returns res, not a zero value. An archive-level failure
	// partway through still extracted whatever came before it, and discarding
	// that is the behaviour this reporting exists to remove.
	logger.Info("rarengine: starting extraction pipeline", "output_dir", absOutputDir)
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		header, err := sd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				// ErrNoNextVolume means two different things depending on
				// what was in flight. With nothing in progress the archive
				// simply ended. Reaching the drain of a member this loop
				// skipped, it means that member never completed -- and
				// treating it as an ordinary end-of-archive reported total
				// success while a stale file sat at its destination.
				if unread != nil && !errors.Is(err, io.EOF) {
					logger.Warn("rarengine: skipping damaged entry", "name", unread.Name, "err", err)
					res.Damaged = append(res.Damaged, DamagedEntry{Header: unread, Err: err})
				}
				break
			}
			// Damage reaches this site for a member that was never read --
			// a directory entry, or a file skipped because it already
			// existed -- which Next drains on the caller's behalf. A member
			// that WAS read has already been recorded below and arrives
			// here only carrying its verdict; see recorded.
			if d, ok := asDamaged(err); ok {
				// A file whose read already failed reaches here a second time,
				// now carrying its verdict. Recording it again would report
				// one damaged member as two.
				if !recorded {
					logger.Warn("rarengine: skipping damaged entry", "name", d.Header.Name, "err", d.Err)
					res.Damaged = append(res.Damaged, d)
				}
				recorded = false
				unread = nil
				continue
			}
			return res, fmt.Errorf("rarengine: read next file: %w", err)
		}
		recorded = false
		unread = nil

		filePath, streamErr, err := extractEntry(ctx, root, sd, header, opts, absOutputDir, logger)
		if err != nil {
			return res, err
		}
		if streamErr != nil {
			// Recorded here rather than from the FileError below because the
			// two sites see different things. A file that reached its
			// declared size and then failed its CRC32 surfaces the mismatch
			// during the read and Next afterwards returns the NEXT header
			// cleanly, so waiting for a FileError would drop that member from
			// both Files and Damaged and report the archive as fully
			// extracted. The header needed to describe it is already in hand.
			logger.Warn("rarengine: skipping damaged entry", "name", header.Name, "err", streamErr)
			res.Damaged = append(res.Damaged, DamagedEntry{Header: header, Err: streamErr})
			recorded = true
			unread = nil
			continue
		}
		if filePath != "" {
			res.Files = append(res.Files, filePath)
			unread = nil
			continue
		}
		// Read to completion is what clears unread; returning no path means
		// the member still owes its payload to the drain Next performs.
		unread = header
	}

	logger.Info("rarengine: extraction pipeline complete",
		"extracted_count", len(res.Files), "damaged_count", len(res.Damaged))
	return res, nil
}

func uniquePath(root *os.Root, destRel string) string {
	if _, err := root.Stat(destRel); err != nil {
		return destRel // doesn't exist, use as-is
	}

	dir := filepath.Dir(destRel)
	base := filepath.Base(destRel)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	for i := 1; i < 10000; i++ {
		var candidate string
		if dir == "." {
			candidate = fmt.Sprintf("%s_%d%s", name, i, ext)
		} else {
			candidate = filepath.Join(dir, fmt.Sprintf("%s_%d%s", name, i, ext))
		}
		if _, err := root.Stat(candidate); err != nil {
			return candidate
		}
	}

	return destRel
}

func discoverVolumes(firstVol string) ([]string, error) {
	if strings.Contains(firstVol, ".part") {
		return discoverPartVolumes(firstVol)
	}

	ext := strings.ToLower(filepath.Ext(firstVol))
	if ext == ".rar" || (len(ext) == 4 && ext[1] == 'r' && ext[2] >= '0' && ext[2] <= '9' && ext[3] >= '0' && ext[3] <= '9') {
		return discoverClassicVolumes(firstVol)
	}

	return []string{firstVol}, nil
}

func discoverPartVolumes(firstVol string) ([]string, error) {
	idx := strings.Index(firstVol, ".part")
	if idx == -1 {
		return []string{firstVol}, nil
	}
	prefix := firstVol[:idx+5]
	remaining := firstVol[idx+5:]

	var numStr strings.Builder
	var suffix string
	for i, c := range remaining {
		if c >= '0' && c <= '9' {
			numStr.WriteString(string(c))
		} else {
			suffix = remaining[i:]
			break
		}
	}

	if numStr.String() == "" {
		return []string{firstVol}, nil
	}

	isZeroPadded := len(numStr.String()) > 1 && numStr.String()[0] == '0'

	var volumes []string
	partNum := 1
	for {
		var volPath string
		if isZeroPadded {
			volPath = fmt.Sprintf("%s%0*d%s", prefix, len(numStr.String()), partNum, suffix)
		} else {
			volPath = fmt.Sprintf("%s%d%s", prefix, partNum, suffix)
		}

		if _, err := os.Stat(volPath); err != nil {
			if os.IsNotExist(err) {
				if partNum > 1 {
					break
				}
				volPath = firstVol
				if _, err := os.Stat(volPath); err == nil {
					volumes = append(volumes, volPath)
				}
				break
			}
			return nil, err
		}
		volumes = append(volumes, volPath)
		partNum++
	}

	return volumes, nil
}

func discoverClassicVolumes(firstVol string) ([]string, error) {
	ext := filepath.Ext(firstVol)
	prefix := firstVol[:len(firstVol)-len(ext)]

	var volumes []string

	// Check if archive.rar exists
	rarPath := prefix + ".rar"
	if _, err := os.Stat(rarPath); err == nil {
		volumes = append(volumes, rarPath)
	}

	// Scan from .r00 up to .r99 contiguous sequence
	for i := range 100 {
		volPath := fmt.Sprintf("%s.r%02d", prefix, i)
		if _, err := os.Stat(volPath); err == nil {
			alreadyAdded := slices.Contains(volumes, volPath)
			if !alreadyAdded {
				volumes = append(volumes, volPath)
			}
		} else if os.IsNotExist(err) {
			if i > 0 || len(volumes) > 0 {
				break
			}
		} else {
			return nil, err
		}
	}

	if len(volumes) == 0 {
		if _, err := os.Stat(firstVol); err == nil {
			return []string{firstVol}, nil
		}
	}
	return volumes, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *contextReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}
