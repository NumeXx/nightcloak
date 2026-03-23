package cloak

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// skipIfNoExiftool skips the test if exiftool is not installed.
func skipIfNoExiftool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("exiftool"); err != nil {
		t.Skip("exiftool not installed, skipping integration test")
	}
}

// skipIfNoFFmpeg skips the test if ffmpeg is not installed.
func skipIfNoFFmpeg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed, skipping test JPEG creation")
	}
}

// createTestJPEG generates a real 8x8 JPEG using ffmpeg.
// exiftool requires a structurally complete JPEG (with SOS/image data)
// to write metadata — bare SOI+APP0+EOI is not enough.
func createTestJPEG(t *testing.T, dir string) string {
	t.Helper()
	skipIfNoFFmpeg(t)

	path := filepath.Join(dir, "test.jpg")
	cmd := exec.Command("ffmpeg",
		"-f", "lavfi", "-i", "color=white:s=8x8:d=1",
		"-frames:v", "1", "-y", path,
	)
	cmd.Stderr = nil // suppress ffmpeg banner
	if err := cmd.Run(); err != nil {
		t.Fatalf("creating test JPEG via ffmpeg: %v", err)
	}
	return path
}

func TestIntegration_HideReveal_StringPayload(t *testing.T) {
	skipIfNoExiftool(t)

	dir := t.TempDir()
	carrier := createTestJPEG(t, dir)
	output := filepath.Join(dir, "output.jpg")

	payload := []byte("this is a secret message")

	// Hide
	err := Hide(HideOpts{
		CarrierPath: carrier,
		OutputPath:  output,
		Payload:     payload,
		Type:        PayloadString,
	})
	if err != nil {
		t.Fatalf("Hide error: %v", err)
	}

	// Verify output file exists and is different from input.
	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty")
	}

	// Reveal
	result, err := Reveal(output)
	if err != nil {
		t.Fatalf("Reveal error: %v", err)
	}

	if result.Type != PayloadString {
		t.Errorf("type = %d, want PayloadString", result.Type)
	}
	if string(result.Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", result.Payload, payload)
	}
}

func TestIntegration_HideReveal_FilePayload(t *testing.T) {
	skipIfNoExiftool(t)

	dir := t.TempDir()
	carrier := createTestJPEG(t, dir)
	output := filepath.Join(dir, "output.jpg")

	payload := []byte("binary file content \x00\xFF\x80")
	payloadName := "secret.bin"

	// Hide
	err := Hide(HideOpts{
		CarrierPath: carrier,
		OutputPath:  output,
		Payload:     payload,
		PayloadName: payloadName,
		Type:        PayloadFile,
	})
	if err != nil {
		t.Fatalf("Hide error: %v", err)
	}

	// Reveal
	result, err := Reveal(output)
	if err != nil {
		t.Fatalf("Reveal error: %v", err)
	}

	if result.Type != PayloadFile {
		t.Errorf("type = %d, want PayloadFile", result.Type)
	}
	if result.PayloadName != payloadName {
		t.Errorf("name = %q, want %q", result.PayloadName, payloadName)
	}
	if string(result.Payload) != string(payload) {
		t.Errorf("payload mismatch")
	}
}

func TestIntegration_HideReveal_InPlace(t *testing.T) {
	skipIfNoExiftool(t)

	dir := t.TempDir()
	carrier := createTestJPEG(t, dir)

	payload := []byte("in-place test")

	// Hide with no OutputPath — should replace carrier.
	err := Hide(HideOpts{
		CarrierPath: carrier,
		Payload:     payload,
		Type:        PayloadString,
	})
	if err != nil {
		t.Fatalf("Hide error: %v", err)
	}

	// The .mod file should not exist (it was renamed over the original).
	modPath := filepath.Join(dir, "test.mod.jpg")
	if _, err := os.Stat(modPath); err == nil {
		t.Error(".mod file should not exist after in-place replacement")
	}

	// Reveal from the original path.
	result, err := Reveal(carrier)
	if err != nil {
		t.Fatalf("Reveal error: %v", err)
	}
	if string(result.Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", result.Payload, payload)
	}
}

func TestIntegration_HideReveal_LargePayload(t *testing.T) {
	skipIfNoExiftool(t)

	dir := t.TempDir()
	carrier := createTestJPEG(t, dir)
	output := filepath.Join(dir, "output.jpg")

	// 500KB payload — well beyond typical ARG_MAX limits.
	// This tests that our -@ - streaming approach actually works.
	payload := make([]byte, 500_000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	err := Hide(HideOpts{
		CarrierPath: carrier,
		OutputPath:  output,
		Payload:     payload,
		PayloadName: "large.bin",
		Type:        PayloadFile,
	})
	if err != nil {
		t.Fatalf("Hide error: %v", err)
	}

	result, err := Reveal(output)
	if err != nil {
		t.Fatalf("Reveal error: %v", err)
	}

	if len(result.Payload) != len(payload) {
		t.Fatalf("payload length = %d, want %d", len(result.Payload), len(payload))
	}
	for i := range payload {
		if result.Payload[i] != payload[i] {
			t.Fatalf("payload byte %d: got %02x, want %02x", i, result.Payload[i], payload[i])
		}
	}
}

func TestIntegration_Reveal_NoPayload(t *testing.T) {
	skipIfNoExiftool(t)

	dir := t.TempDir()
	carrier := createTestJPEG(t, dir)

	// Reveal from a file with no cloak data.
	_, err := Reveal(carrier)
	if err == nil {
		t.Fatal("expected error for file without cloak data")
	}
}
