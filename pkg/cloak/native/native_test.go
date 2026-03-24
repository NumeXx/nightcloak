package native

import (
	"bytes"
	"crypto/hmac"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

// createTestPNG generates a valid 1x1 white PNG in memory.
func createTestPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.White)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("creating test PNG: %v", err)
	}
	return buf.Bytes()
}

func TestPNG_InjectExtract_RoundTrip(t *testing.T) {
	carrier := createTestPNG(t)
	payload := []byte("this is a secret payload embedded natively")
	password := "testpass"

	// Inject.
	var injected bytes.Buffer
	err := PNGInject(bytes.NewReader(carrier), &injected, payload, password)
	if err != nil {
		t.Fatalf("PNGInject error: %v", err)
	}

	// Verify the result is still a valid PNG.
	_, err = png.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("injected PNG is not valid: %v", err)
	}

	// Extract.
	extracted, err := PNGExtract(bytes.NewReader(injected.Bytes()), password)
	if err != nil {
		t.Fatalf("PNGExtract error: %v", err)
	}

	if !bytes.Equal(extracted, payload) {
		t.Errorf("payload mismatch: got %q, want %q", extracted, payload)
	}
}

func TestPNG_WrongPassword(t *testing.T) {
	carrier := createTestPNG(t)
	payload := []byte("secret")

	var injected bytes.Buffer
	PNGInject(bytes.NewReader(carrier), &injected, payload, "correct")

	_, err := PNGExtract(bytes.NewReader(injected.Bytes()), "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestPNG_NoPayload(t *testing.T) {
	carrier := createTestPNG(t)

	_, err := PNGExtract(bytes.NewReader(carrier), "anypass")
	if err == nil {
		t.Fatal("expected error for clean PNG, got nil")
	}
}

func TestPNG_LargePayload(t *testing.T) {
	carrier := createTestPNG(t)

	// 100KB payload — well beyond what a CLI argument could carry.
	payload := make([]byte, 100_000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var injected bytes.Buffer
	err := PNGInject(bytes.NewReader(carrier), &injected, payload, "bigpass")
	if err != nil {
		t.Fatalf("PNGInject error: %v", err)
	}

	// Still valid PNG.
	_, err = png.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("injected PNG is not valid: %v", err)
	}

	// Roundtrip.
	extracted, err := PNGExtract(bytes.NewReader(injected.Bytes()), "bigpass")
	if err != nil {
		t.Fatalf("PNGExtract error: %v", err)
	}
	if len(extracted) != len(payload) {
		t.Fatalf("length mismatch: got %d, want %d", len(extracted), len(payload))
	}
	if !bytes.Equal(extracted, payload) {
		t.Error("payload bytes differ")
	}
}

func TestPNG_BinaryPayload(t *testing.T) {
	carrier := createTestPNG(t)
	// Payload with null bytes, high bytes — the full byte range.
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}

	var injected bytes.Buffer
	PNGInject(bytes.NewReader(carrier), &injected, payload, "binpass")

	extracted, err := PNGExtract(bytes.NewReader(injected.Bytes()), "binpass")
	if err != nil {
		t.Fatalf("PNGExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Error("binary payload roundtrip failed")
	}
}

func TestPNG_InvalidFile(t *testing.T) {
	notPNG := []byte("this is not a PNG file at all")

	var out bytes.Buffer
	err := PNGInject(bytes.NewReader(notPNG), &out, []byte("x"), "pass")
	if err == nil {
		t.Fatal("expected error for non-PNG input")
	}

	_, err = PNGExtract(bytes.NewReader(notPNG), "pass")
	if err == nil {
		t.Fatal("expected error for non-PNG input")
	}
}

func TestPNG_ImageDataPreserved(t *testing.T) {
	// Create a 4x4 image with known pixel values.
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 60), G: uint8(y * 60), B: 128, A: 255})
		}
	}
	var carrier bytes.Buffer
	png.Encode(&carrier, img)

	// Inject.
	var injected bytes.Buffer
	PNGInject(bytes.NewReader(carrier.Bytes()), &injected, []byte("payload"), "pass")

	// Decode the injected PNG and compare pixels.
	decoded, err := png.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("decoding injected PNG: %v", err)
	}
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			origR, origG, origB, origA := img.At(x, y).RGBA()
			gotR, gotG, gotB, gotA := decoded.At(x, y).RGBA()
			if origR != gotR || origG != gotG || origB != gotB || origA != gotA {
				t.Errorf("pixel (%d,%d) changed after injection", x, y)
			}
		}
	}
}

func TestSentinel_PasswordDependent(t *testing.T) {
	s1 := sentinel("password1")
	s2 := sentinel("password2")

	if hmac.Equal(s1, s2) {
		t.Error("different passwords produced identical sentinels")
	}
	if len(s1) != sentinelSize {
		t.Errorf("sentinel length = %d, want %d", len(s1), sentinelSize)
	}
}

func TestSentinel_Deterministic(t *testing.T) {
	s1 := sentinel("same")
	s2 := sentinel("same")

	if !hmac.Equal(s1, s2) {
		t.Error("same password produced different sentinels")
	}
}

func TestPNG_MultipleTextChunks(t *testing.T) {
	// Inject twice with different passwords. Only the matching one extracts.
	carrier := createTestPNG(t)

	var first bytes.Buffer
	PNGInject(bytes.NewReader(carrier), &first, []byte("first-payload"), "pass1")

	var second bytes.Buffer
	PNGInject(bytes.NewReader(first.Bytes()), &second, []byte("second-payload"), "pass2")

	// Extract with pass1 — should get first payload.
	got1, err := PNGExtract(bytes.NewReader(second.Bytes()), "pass1")
	if err != nil {
		t.Fatalf("extracting first payload: %v", err)
	}
	if string(got1) != "first-payload" {
		t.Errorf("first payload = %q, want %q", got1, "first-payload")
	}

	// Extract with pass2 — should get second payload.
	got2, err := PNGExtract(bytes.NewReader(second.Bytes()), "pass2")
	if err != nil {
		t.Fatalf("extracting second payload: %v", err)
	}
	if string(got2) != "second-payload" {
		t.Errorf("second payload = %q, want %q", got2, "second-payload")
	}

	// Extract with pass3 — should fail.
	_, err = PNGExtract(bytes.NewReader(second.Bytes()), "pass3")
	if err == nil {
		t.Fatal("expected error for non-matching password")
	}
	if !strings.Contains(err.Error(), "no nightcloak payload found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// JPEG tests
// ---------------------------------------------------------------------------

func createTestJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 60), G: uint8(y * 60), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("creating test JPEG: %v", err)
	}
	return buf.Bytes()
}

func TestJPEG_InjectExtract_RoundTrip(t *testing.T) {
	carrier := createTestJPEG(t)
	payload := []byte("secret JPEG payload injected natively")
	password := "jpegpass"

	var injected bytes.Buffer
	err := JPEGInject(bytes.NewReader(carrier), &injected, payload, password)
	if err != nil {
		t.Fatalf("JPEGInject error: %v", err)
	}

	// Verify the result is still a valid JPEG.
	_, err = jpeg.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("injected JPEG is not valid: %v", err)
	}

	extracted, err := JPEGExtract(bytes.NewReader(injected.Bytes()), password)
	if err != nil {
		t.Fatalf("JPEGExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("payload mismatch: got %q, want %q", extracted, payload)
	}
}

func TestJPEG_WrongPassword(t *testing.T) {
	carrier := createTestJPEG(t)

	var injected bytes.Buffer
	JPEGInject(bytes.NewReader(carrier), &injected, []byte("secret"), "correct")

	_, err := JPEGExtract(bytes.NewReader(injected.Bytes()), "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestJPEG_NoPayload(t *testing.T) {
	carrier := createTestJPEG(t)

	_, err := JPEGExtract(bytes.NewReader(carrier), "anypass")
	if err == nil {
		t.Fatal("expected error for clean JPEG")
	}
}

func TestJPEG_LargePayload(t *testing.T) {
	carrier := createTestJPEG(t)

	// 200KB payload — requires multiple COM segments (each max 65533).
	payload := make([]byte, 200_000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var injected bytes.Buffer
	err := JPEGInject(bytes.NewReader(carrier), &injected, payload, "bigpass")
	if err != nil {
		t.Fatalf("JPEGInject error: %v", err)
	}

	// Still valid.
	_, err = jpeg.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("injected JPEG is not valid: %v", err)
	}

	extracted, err := JPEGExtract(bytes.NewReader(injected.Bytes()), "bigpass")
	if err != nil {
		t.Fatalf("JPEGExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("large payload mismatch: got %d bytes, want %d", len(extracted), len(payload))
	}
}

func TestJPEG_BinaryPayload(t *testing.T) {
	carrier := createTestJPEG(t)
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}

	var injected bytes.Buffer
	JPEGInject(bytes.NewReader(carrier), &injected, payload, "binpass")

	extracted, err := JPEGExtract(bytes.NewReader(injected.Bytes()), "binpass")
	if err != nil {
		t.Fatalf("JPEGExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Error("binary payload roundtrip failed")
	}
}

func TestJPEG_InvalidFile(t *testing.T) {
	notJPEG := []byte("this is not a JPEG")

	var out bytes.Buffer
	err := JPEGInject(bytes.NewReader(notJPEG), &out, []byte("x"), "pass")
	if err == nil {
		t.Fatal("expected error for non-JPEG input")
	}

	_, err = JPEGExtract(bytes.NewReader(notJPEG), "pass")
	if err == nil {
		t.Fatal("expected error for non-JPEG input")
	}
}

func TestJPEG_ImageDataPreserved(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 60), G: uint8(y * 60), B: 128, A: 255})
		}
	}
	var carrier bytes.Buffer
	jpeg.Encode(&carrier, img, &jpeg.Options{Quality: 100})

	var injected bytes.Buffer
	JPEGInject(bytes.NewReader(carrier.Bytes()), &injected, []byte("payload"), "pass")

	// Decode both and compare dimensions (JPEG is lossy so pixel
	// comparison is not reliable, but dimensions must match).
	orig, _ := jpeg.Decode(bytes.NewReader(carrier.Bytes()))
	decoded, err := jpeg.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("decoding injected JPEG: %v", err)
	}
	if orig.Bounds() != decoded.Bounds() {
		t.Errorf("image dimensions changed: %v vs %v", orig.Bounds(), decoded.Bounds())
	}
}
