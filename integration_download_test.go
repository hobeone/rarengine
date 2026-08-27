package rarengine_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/hobeone/rarengine"
)

func downloadTestFile(t *testing.T, filename string) []byte {
	t.Helper()
	url := "https://raw.githubusercontent.com/ssokolow/rar-test-files/master/build/" + filename
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Skipf("Skipping test; network request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("Skipping test; server returned status: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read downloaded data: %v", err)
	}
	return data
}

func TestIntegration_Download_RAR5(t *testing.T) {
	data := downloadTestFile(t, "testfile.rar5.rar")

	volumes := make(chan io.ReadCloser, 1)
	volumes <- io.NopCloser(bytes.NewReader(data))
	close(volumes)

	r := rarengine.NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	if e.Header.Name != "testfile.txt" {
		t.Errorf("expected filename 'testfile.txt', got %q", e.Header.Name)
	}

	buf, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	expectedContent := "Testing 123\n"
	if string(buf) != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, string(buf))
	}
}

func TestIntegration_Download_RAR5_Solid(t *testing.T) {
	data := downloadTestFile(t, "testfile.rar5.solid.rar")

	volumes := make(chan io.ReadCloser, 1)
	volumes <- io.NopCloser(bytes.NewReader(data))
	close(volumes)

	r := rarengine.NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	if e.Header.Name != "testfile.txt" {
		t.Errorf("expected filename 'testfile.txt', got %q", e.Header.Name)
	}

	buf, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	expectedContent := "Testing 123\n"
	if string(buf) != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, string(buf))
	}
}
