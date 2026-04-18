package native

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func createPolyTestJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(0, 0, color.White)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatalf("creating JPEG: %v", err)
	}
	return buf.Bytes()
}

func createPolyTestPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.White)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("creating PNG: %v", err)
	}
	return buf.Bytes()
}

func createPolyTestPDF() []byte {
	return []byte("%PDF-1.0\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 1\n0000000000 65535 f \ntrailer<</Size 1>>\nstartxref\n9\n%%EOF\n")
}

func testPolyRoundTrip(t *testing.T, carrier []byte, ext string) {
	t.Helper()
	payload := []byte("encrypted-payload-bytes-for-polyglot-test")

	poly, err := PolyHide(carrier, payload, ext)
	if err != nil {
		t.Fatalf("PolyHide: %v", err)
	}

	// Polyglot must be larger than carrier.
	if len(poly) <= len(carrier) {
		t.Fatalf("polyglot (%d) not larger than carrier (%d)", len(poly), len(carrier))
	}

	got, err := PolyReveal(poly)
	if err != nil {
		t.Fatalf("PolyReveal: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reveal mismatch: got %q, want %q", got, payload)
	}

	wiped, err := PolyWipe(poly)
	if err != nil {
		t.Fatalf("PolyWipe: %v", err)
	}

	// Wiped result must equal the trimmed carrier (not necessarily the original,
	// since trimCarrier may strip trailing padding the encoder added).
	trimmed, err := trimCarrier(carrier, ext)
	if err != nil {
		t.Fatalf("trimCarrier: %v", err)
	}
	if !bytes.Equal(wiped, trimmed) {
		t.Fatalf("wipe mismatch: got %d bytes, want %d bytes", len(wiped), len(trimmed))
	}
}

func TestPolyHide_JPEG_RoundTrip(t *testing.T) {
	testPolyRoundTrip(t, createPolyTestJPEG(t), ".jpg")
}

func TestPolyHide_PNG_RoundTrip(t *testing.T) {
	testPolyRoundTrip(t, createPolyTestPNG(t), ".png")
}

func TestPolyHide_PDF_RoundTrip(t *testing.T) {
	testPolyRoundTrip(t, createPolyTestPDF(), ".pdf")
}

func TestPolyHide_UnsupportedExt(t *testing.T) {
	_, err := PolyHide([]byte("data"), []byte("payload"), ".mp3")
	if err == nil {
		t.Fatal("expected error for unsupported extension")
	}
}

func TestPolyReveal_NotAPolyglot(t *testing.T) {
	_, err := PolyReveal([]byte("this is not a polyglot"))
	if err == nil {
		t.Fatal("expected error for non-polyglot input")
	}
}

func TestPolyWipe_UnknownFormat(t *testing.T) {
	_, err := PolyWipe([]byte("not a known format"))
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestPolyHide_JPEG_CarrierStillValid(t *testing.T) {
	carrier := createPolyTestJPEG(t)
	poly, err := PolyHide(carrier, []byte("test payload"), ".jpg")
	if err != nil {
		t.Fatalf("PolyHide: %v", err)
	}
	// JPEG parsers stop at FFD9; the polyglot must start with JPEG SOI and contain FFD9.
	if poly[0] != 0xFF || poly[1] != 0xD8 {
		t.Fatal("polyglot does not start with JPEG SOI")
	}
	hasEOI := false
	for i := 0; i < len(poly)-1; i++ {
		if poly[i] == 0xFF && poly[i+1] == 0xD9 {
			hasEOI = true
			break
		}
	}
	if !hasEOI {
		t.Fatal("polyglot does not contain JPEG EOI marker")
	}
}

func TestPolyHide_PNG_CarrierStillValid(t *testing.T) {
	carrier := createPolyTestPNG(t)
	poly, err := PolyHide(carrier, []byte("test payload"), ".png")
	if err != nil {
		t.Fatalf("PolyHide: %v", err)
	}
	// Must start with PNG magic.
	if !bytes.HasPrefix(poly, pngSignatureBytes) {
		t.Fatal("polyglot does not start with PNG signature")
	}
}

func TestPolyHide_MultiplePayloads(t *testing.T) {
	carrier := createPolyTestJPEG(t)
	payloads := [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte("A"), 1024),
		bytes.Repeat([]byte{0x00, 0xFF}, 512),
	}
	for _, p := range payloads {
		poly, err := PolyHide(carrier, p, ".jpg")
		if err != nil {
			t.Fatalf("PolyHide: %v", err)
		}
		got, err := PolyReveal(poly)
		if err != nil {
			t.Fatalf("PolyReveal: %v", err)
		}
		if !bytes.Equal(got, p) {
			t.Fatal("round-trip mismatch")
		}
	}
}
