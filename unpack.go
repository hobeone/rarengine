package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// UnpackOptions configures the high-level archive extraction process.
type UnpackOptions struct {
	Password string
	Logger   *slog.Logger
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

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("rarengine: sort: open %s: %w", p, err)
		}

		volIdx, err := readVolumeIndex(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("rarengine: sort: parse %s: %w", p, err)
		}

		vols = append(vols, volumeInfo{
			path:  p,
			index: volIdx,
		})
	}

	sort.Slice(vols, func(i, j int) bool {
		return vols[i].index < vols[j].index
	})

	sorted := make([]string, len(vols))
	for i, v := range vols {
		sorted[i] = v.path
	}
	return sorted, nil
}

func readVolumeIndex(r io.Reader) (int, error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return 0, err
	}
	expectedMagic := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}
	if !bytes.Equal(magic[:], expectedMagic) {
		return 0, errors.New("invalid RAR5 magic signature")
	}

	h, err := ReadBlockHeader(r)
	if err != nil {
		return 0, err
	}

	ah, err := ParseArchiveHeader(h)
	if err != nil {
		return 0, err
	}

	if ah.VolumeNumber < 0 {
		return 0, nil
	}
	return ah.VolumeNumber, nil
}

// UnpackDir automatically discovers, sorts, opens, and extracts a set of RAR5
// archive volume files from the same directory starting at firstVolumePath.
func UnpackDir(firstVolumePath string, outputDir string, opts UnpackOptions) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	logger.Info("rarengine: starting volume discovery", "first_volume", firstVolumePath)
	vols, err := discoverVolumes(firstVolumePath)
	if err != nil {
		return fmt.Errorf("rarengine: discover volumes: %w", err)
	}
	logger.Info("rarengine: discovered volumes", "count", len(vols), "paths", vols)

	logger.Info("rarengine: sorting volumes by internal headers")
	sortedVols, err := SortVolumes(vols)
	if err != nil {
		return fmt.Errorf("rarengine: sort volumes: %w", err)
	}
	logger.Info("rarengine: sorted volumes order", "paths", sortedVols)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("rarengine: create output dir: %w", err)
	}

	volumesChan := make(chan io.ReadCloser, len(sortedVols))
	for _, volPath := range sortedVols {
		vf, err := os.Open(volPath)
		if err != nil {
			close(volumesChan)
			for v := range volumesChan {
				_ = v.Close()
			}
			return fmt.Errorf("rarengine: open volume %s: %w", volPath, err)
		}
		volumesChan <- vf
	}
	close(volumesChan)

	sd := NewStreamDecompressor(volumesChan)
	if opts.Password != "" {
		sd.SetPassword(opts.Password)
	}

	logger.Info("rarengine: starting extraction pipeline", "output_dir", outputDir)
	for {
		header, err := sd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				break
			}
			return fmt.Errorf("rarengine: read next file: %w", err)
		}

		targetPath := filepath.Join(outputDir, header.Name)
		logger.Info("rarengine: extracting entry", "name", header.Name, "size", header.UnpackedSize, "is_dir", header.IsDir)

		if header.IsDir {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("rarengine: mkdir %s: %w", targetPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("rarengine: mkdir parent %s: %w", filepath.Dir(targetPath), err)
		}

		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.Mode())
		if err != nil {
			return fmt.Errorf("rarengine: create file %s: %w", targetPath, err)
		}

		n, err := io.Copy(out, sd)
		_ = out.Close()
		if err != nil {
			return fmt.Errorf("rarengine: write file %s: %w", targetPath, err)
		}

		if !header.ModificationTime.IsZero() {
			_ = os.Chtimes(targetPath, header.ModificationTime, header.ModificationTime)
		}

		logger.Info("rarengine: extracted entry complete", "name", header.Name, "written_bytes", n)
	}

	logger.Info("rarengine: extraction pipeline complete")
	return nil
}

func discoverVolumes(firstVol string) ([]string, error) {
	if !strings.Contains(firstVol, ".part") {
		return []string{firstVol}, nil
	}

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
