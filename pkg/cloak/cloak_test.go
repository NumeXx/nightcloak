package cloak

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit tests: parsing logic (no external tools needed)
// ---------------------------------------------------------------------------

func TestParseDescription_FilePayload(t *testing.T) {
	name := "secret.txt"
	data := []byte("encrypted-file-content")
	name64 := base64.StdEncoding.EncodeToString([]byte(name))
	data64 := base64.StdEncoding.EncodeToString(data)
	desc := fmt.Sprintf("N:%s;F:%s", name64, data64)

	result, err := parseDescription(desc)
	if err != nil {
		t.Fatalf("parseDescription error: %v", err)
	}

	if result.Type != PayloadFile {
		t.Errorf("type = %d, want PayloadFile", result.Type)
	}
	if result.PayloadName != name {
		t.Errorf("name = %q, want %q", result.PayloadName, name)
	}
	if string(result.Payload) != string(data) {
		t.Errorf("payload = %q, want %q", result.Payload, data)
	}
}

func TestParseDescription_StringPayload(t *testing.T) {
	data := []byte("encrypted-string-content")
	data64 := base64.StdEncoding.EncodeToString(data)
	desc := fmt.Sprintf("S:%s", data64)

	result, err := parseDescription(desc)
	if err != nil {
		t.Fatalf("parseDescription error: %v", err)
	}

	if result.Type != PayloadString {
		t.Errorf("type = %d, want PayloadString", result.Type)
	}
	if result.PayloadName != "" {
		t.Errorf("name = %q, want empty", result.PayloadName)
	}
	if string(result.Payload) != string(data) {
		t.Errorf("payload = %q, want %q", result.Payload, data)
	}
}

func TestParseDescription_Empty(t *testing.T) {
	_, err := parseDescription("")
	if err == nil {
		t.Fatal("expected error for empty description")
	}
}

func TestParseDescription_UnknownPrefix(t *testing.T) {
	_, err := parseDescription("X:some-data")
	if err == nil {
		t.Fatal("expected error for unknown prefix")
	}
}

func TestParseDescription_MalformedFile_NoSemicolon(t *testing.T) {
	_, err := parseDescription("N:name-without-semicolon")
	if err == nil {
		t.Fatal("expected error for missing semicolon")
	}
}

func TestParseDescription_MalformedFile_NoFPrefix(t *testing.T) {
	name64 := base64.StdEncoding.EncodeToString([]byte("test.txt"))
	_, err := parseDescription(fmt.Sprintf("N:%s;MISSING:data", name64))
	if err == nil {
		t.Fatal("expected error for missing F: prefix")
	}
}

func TestParseExifJSON_ValidCloakData(t *testing.T) {
	data := []byte("test-payload")
	data64 := base64.StdEncoding.EncodeToString(data)

	entry := []map[string]interface{}{
		{
			"SourceFile":  "test.jpg",
			"Comment":     TagLine,
			"Description": fmt.Sprintf("S:%s", data64),
		},
	}
	jsonBytes, _ := json.Marshal(entry)

	result, err := parseExifJSON(jsonBytes)
	if err != nil {
		t.Fatalf("parseExifJSON error: %v", err)
	}
	if string(result.Payload) != string(data) {
		t.Errorf("payload = %q, want %q", result.Payload, data)
	}
}

func TestParseExifJSON_NoCloakData(t *testing.T) {
	entry := []map[string]interface{}{
		{
			"SourceFile": "test.jpg",
			"Comment":    "Just a regular photo",
		},
	}
	jsonBytes, _ := json.Marshal(entry)

	_, err := parseExifJSON(jsonBytes)
	if err == nil {
		t.Fatal("expected error for file without cloak data")
	}
}

func TestParseExifJSON_PDFWorkaround(t *testing.T) {
	// PDF files don't get the Comment tag — but Description with N:/S: prefix
	// should still work (the original cloak.sh's FIXME workaround).
	data := []byte("pdf-payload")
	data64 := base64.StdEncoding.EncodeToString(data)

	entry := []map[string]interface{}{
		{
			"SourceFile":  "document.pdf",
			"Description": fmt.Sprintf("S:%s", data64),
			// No "Comment" field at all — simulating the PDF bug.
		},
	}
	jsonBytes, _ := json.Marshal(entry)

	result, err := parseExifJSON(jsonBytes)
	if err != nil {
		t.Fatalf("PDF workaround failed: %v", err)
	}
	if string(result.Payload) != string(data) {
		t.Errorf("payload = %q, want %q", result.Payload, data)
	}
}

func TestParseExifJSON_EmptyArray(t *testing.T) {
	_, err := parseExifJSON([]byte("[]"))
	if err == nil {
		t.Fatal("expected error for empty tag array")
	}
}

func TestParseExifJSON_InvalidJSON(t *testing.T) {
	_, err := parseExifJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

func TestValidateHideOpts_EmptyCarrier(t *testing.T) {
	err := validateHideOpts(HideOpts{Payload: []byte("x")})
	if err == nil {
		t.Fatal("expected error for empty carrier path")
	}
}

func TestValidateHideOpts_EmptyPayload(t *testing.T) {
	// Use a path that likely exists to isolate the payload validation.
	err := validateHideOpts(HideOpts{CarrierPath: "/dev/null"})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestValidateHideOpts_FileMissingName(t *testing.T) {
	err := validateHideOpts(HideOpts{
		CarrierPath: "/dev/null",
		Payload:     []byte("x"),
		Type:        PayloadFile,
	})
	if err == nil {
		t.Fatal("expected error for file payload without name")
	}
}

func TestResolveOutput_Explicit(t *testing.T) {
	opts := HideOpts{
		CarrierPath: "/photos/test.jpg",
		OutputPath:  "/tmp/out.jpg",
	}
	if got := resolveOutput(opts); got != "/tmp/out.jpg" {
		t.Errorf("resolveOutput = %q, want /tmp/out.jpg", got)
	}
}

func TestResolveOutput_Default(t *testing.T) {
	opts := HideOpts{CarrierPath: "/photos/test.jpg"}
	got := resolveOutput(opts)
	want := "/photos/test.mod.jpg"
	if got != want {
		t.Errorf("resolveOutput = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// ZipFolder tests
// ---------------------------------------------------------------------------

func TestZipFolder_ValidDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create test files inside the directory.
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("alpha"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bravo"), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "c.txt"), []byte("charlie"), 0644)

	zipData, name, err := ZipFolder(dir)
	if err != nil {
		t.Fatalf("ZipFolder error: %v", err)
	}

	if !strings.HasSuffix(name, ".zip") {
		t.Errorf("archive name %q doesn't end with .zip", name)
	}

	if len(zipData) == 0 {
		t.Fatal("zip data is empty")
	}

	// Verify zip contents are readable.
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("reading zip: %v", err)
	}

	names := map[string]bool{}
	for _, f := range r.File {
		names[f.Name] = true
	}
	for _, want := range []string{"a.txt", "b.txt", "sub/c.txt"} {
		if !names[want] {
			t.Errorf("missing %q in zip (got %v)", want, names)
		}
	}
}

func TestZipFolder_NotADirectory(t *testing.T) {
	f, _ := os.CreateTemp("", "notadir")
	f.Close()
	defer os.Remove(f.Name())

	_, _, err := ZipFolder(f.Name())
	if err == nil {
		t.Fatal("expected error for non-directory")
	}
}

func TestZipFolder_NonExistent(t *testing.T) {
	_, _, err := ZipFolder("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestFfmpegExtensions(t *testing.T) {
	yes := []string{".avi", ".ogg"}
	no := []string{".jpg", ".png", ".pdf", ".gif", ".mp3", ".MP3"}

	for _, ext := range yes {
		if !ffmpegExtensions[ext] {
			t.Errorf("%s should route to ffmpeg", ext)
		}
	}
	for _, ext := range no {
		if ffmpegExtensions[ext] {
			t.Errorf("%s should NOT route to ffmpeg", ext)
		}
	}
}
