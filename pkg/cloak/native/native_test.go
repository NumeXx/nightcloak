package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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

// ---------------------------------------------------------------------------
// JPEG EXIF (APP1) tests
// ---------------------------------------------------------------------------

func TestExif_InjectExtract_RoundTrip(t *testing.T) {
	carrier := createTestJPEG(t)
	payload := []byte("stealth EXIF payload via UserComment")
	password := "exifpass"

	var injected bytes.Buffer
	err := JPEGExifInject(bytes.NewReader(carrier), &injected, payload, password)
	if err != nil {
		t.Fatalf("JPEGExifInject error: %v", err)
	}

	// Still a valid JPEG.
	_, err = jpeg.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("injected JPEG is not valid: %v", err)
	}

	extracted, err := JPEGExifExtract(bytes.NewReader(injected.Bytes()), password)
	if err != nil {
		t.Fatalf("JPEGExifExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("payload mismatch: got %q, want %q", extracted, payload)
	}
}

func TestExif_WrongPassword(t *testing.T) {
	carrier := createTestJPEG(t)

	var injected bytes.Buffer
	JPEGExifInject(bytes.NewReader(carrier), &injected, []byte("secret"), "correct")

	_, err := JPEGExifExtract(bytes.NewReader(injected.Bytes()), "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestExif_NoPayload(t *testing.T) {
	carrier := createTestJPEG(t)

	_, err := JPEGExifExtract(bytes.NewReader(carrier), "anypass")
	if err == nil {
		t.Fatal("expected error for clean JPEG")
	}
}

func TestExif_LargePayload(t *testing.T) {
	carrier := createTestJPEG(t)

	// 150KB payload — requires multiple APP1 segments.
	payload := make([]byte, 150_000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var injected bytes.Buffer
	err := JPEGExifInject(bytes.NewReader(carrier), &injected, payload, "bigexif")
	if err != nil {
		t.Fatalf("JPEGExifInject error: %v", err)
	}

	_, err = jpeg.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("injected JPEG is not valid: %v", err)
	}

	extracted, err := JPEGExifExtract(bytes.NewReader(injected.Bytes()), "bigexif")
	if err != nil {
		t.Fatalf("JPEGExifExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("large payload mismatch: got %d bytes, want %d", len(extracted), len(payload))
	}
}

func TestExif_BinaryPayload(t *testing.T) {
	carrier := createTestJPEG(t)
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}

	var injected bytes.Buffer
	JPEGExifInject(bytes.NewReader(carrier), &injected, payload, "binexif")

	extracted, err := JPEGExifExtract(bytes.NewReader(injected.Bytes()), "binexif")
	if err != nil {
		t.Fatalf("JPEGExifExtract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Error("binary payload roundtrip failed")
	}
}

func TestExif_InvalidFile(t *testing.T) {
	notJPEG := []byte("not a jpeg")

	var out bytes.Buffer
	err := JPEGExifInject(bytes.NewReader(notJPEG), &out, []byte("x"), "pass")
	if err == nil {
		t.Fatal("expected error for non-JPEG")
	}

	_, err = JPEGExifExtract(bytes.NewReader(notJPEG), "pass")
	if err == nil {
		t.Fatal("expected error for non-JPEG")
	}
}

func TestExif_PreservesExistingAPP1(t *testing.T) {
	carrier := createTestJPEG(t)

	// Inject via EXIF.
	var injected bytes.Buffer
	JPEGExifInject(bytes.NewReader(carrier), &injected, []byte("test"), "pass")

	// The original JPEG may have APP0 (JFIF). Verify the image still decodes
	// and dimensions are preserved.
	orig, _ := jpeg.Decode(bytes.NewReader(carrier))
	decoded, err := jpeg.Decode(bytes.NewReader(injected.Bytes()))
	if err != nil {
		t.Fatalf("decoding failed: %v", err)
	}
	if orig.Bounds() != decoded.Bounds() {
		t.Errorf("dimensions changed: %v vs %v", orig.Bounds(), decoded.Bounds())
	}
}

func TestExif_COMAndExifIndependent(t *testing.T) {
	// Inject via COM, then via EXIF with different passwords.
	// Both should be independently extractable.
	carrier := createTestJPEG(t)

	var withCOM bytes.Buffer
	JPEGInject(bytes.NewReader(carrier), &withCOM, []byte("com-payload"), "compass")

	var withBoth bytes.Buffer
	JPEGExifInject(bytes.NewReader(withCOM.Bytes()), &withBoth, []byte("exif-payload"), "exifpass")

	// Still valid.
	_, err := jpeg.Decode(bytes.NewReader(withBoth.Bytes()))
	if err != nil {
		t.Fatalf("JPEG with both COM and EXIF is invalid: %v", err)
	}

	// Extract COM.
	comResult, err := JPEGExtract(bytes.NewReader(withBoth.Bytes()), "compass")
	if err != nil {
		t.Fatalf("COM extraction failed: %v", err)
	}
	if string(comResult) != "com-payload" {
		t.Errorf("COM payload = %q, want %q", comResult, "com-payload")
	}

	// Extract EXIF.
	exifResult, err := JPEGExifExtract(bytes.NewReader(withBoth.Bytes()), "exifpass")
	if err != nil {
		t.Fatalf("EXIF extraction failed: %v", err)
	}
	if string(exifResult) != "exif-payload" {
		t.Errorf("EXIF payload = %q, want %q", exifResult, "exif-payload")
	}
}

// ---------------------------------------------------------------------------
// MP3 (ID3v2) tests
// ---------------------------------------------------------------------------

// createTestMP3 generates a minimal MP3 file: just a valid MPEG audio frame
// (Layer 3, 128kbps, 44100Hz, stereo, silent). No ID3v2 tag.
func createTestMP3NoTag(t *testing.T) []byte {
	t.Helper()
	// Valid MPEG1 Layer3 frame header: 0xFFFB9004
	// FF FB = sync + MPEG1 Layer3, 90 = 128kbps 44100Hz, 04 = stereo padded
	// Frame size = 144 * 128000 / 44100 + 1 = 418 bytes
	frame := make([]byte, 418)
	frame[0] = 0xFF
	frame[1] = 0xFB
	frame[2] = 0x90
	frame[3] = 0x04
	return frame
}

// createTestMP3WithTag generates an MP3 with an existing ID3v2.3 tag
// containing a TIT2 (title) frame and padding.
func createTestMP3WithTag(t *testing.T) []byte {
	t.Helper()

	// Build a TIT2 frame: encoding(1) + "Test Title"
	title := []byte("Test Title")
	tit2Data := make([]byte, 1+len(title))
	tit2Data[0] = 0x00 // ISO-8859-1
	copy(tit2Data[1:], title)

	tit2Frame := make([]byte, frameHeaderV23+len(tit2Data))
	copy(tit2Frame[0:4], "TIT2")
	binary.BigEndian.PutUint32(tit2Frame[4:8], uint32(len(tit2Data)))

	copy(tit2Frame[frameHeaderV23:], tit2Data)

	// Tag = TIT2 frame + 2048 bytes padding.
	padding := make([]byte, 2048)
	tagBody := append(tit2Frame, padding...)

	tagSize := encodeSyncsafe(uint32(len(tagBody)))
	header := []byte{
		'I', 'D', '3',
		0x03, 0x00, // v2.3
		0x00,       // no flags
		tagSize[0], tagSize[1], tagSize[2], tagSize[3],
	}

	// Audio frame after the tag.
	audio := createTestMP3NoTag(t)

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(tagBody)
	buf.Write(audio)
	return buf.Bytes()
}

func TestMP3_InjectExtract_NoExistingTag(t *testing.T) {
	carrier := createTestMP3NoTag(t)
	payload := []byte("MP3 native injection without existing tag")
	password := "mp3pass"

	var injected bytes.Buffer
	err := MP3Inject(bytes.NewReader(carrier), &injected, payload, password)
	if err != nil {
		t.Fatalf("MP3Inject error: %v", err)
	}

	// Verify ID3v2 header was created.
	result := injected.Bytes()
	if string(result[0:3]) != "ID3" {
		t.Fatal("injected MP3 does not start with ID3 header")
	}

	extracted, err := MP3Extract(bytes.NewReader(result), password)
	if err != nil {
		t.Fatalf("MP3Extract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("payload mismatch: got %q, want %q", extracted, payload)
	}

	// Verify audio data is preserved at the end.
	// The audio should be findable after the ID3 tag.
	tagSize := decodeSyncsafe(result[6:10])
	audioStart := id3HeaderSize + int(tagSize)
	if audioStart+4 > len(result) {
		t.Fatal("audio data missing after ID3 tag")
	}
	if result[audioStart] != 0xFF || result[audioStart+1] != 0xFB {
		t.Errorf("MPEG sync not found at expected position %d", audioStart)
	}
}

func TestMP3_InjectExtract_ExistingTag(t *testing.T) {
	carrier := createTestMP3WithTag(t)
	payload := []byte("injected into existing tag")
	password := "existpass"

	var injected bytes.Buffer
	err := MP3Inject(bytes.NewReader(carrier), &injected, payload, password)
	if err != nil {
		t.Fatalf("MP3Inject error: %v", err)
	}

	extracted, err := MP3Extract(bytes.NewReader(injected.Bytes()), password)
	if err != nil {
		t.Fatalf("MP3Extract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("payload mismatch: got %q, want %q", extracted, payload)
	}
}

func TestMP3_PreservesExistingFrames(t *testing.T) {
	carrier := createTestMP3WithTag(t)

	var injected bytes.Buffer
	MP3Inject(bytes.NewReader(carrier), &injected, []byte("test"), "pass")

	result := injected.Bytes()
	tagSize := decodeSyncsafe(result[6:10])
	tagBody := result[id3HeaderSize : id3HeaderSize+int(tagSize)]

	// Walk frames, verify TIT2 is still there.
	foundTIT2 := false
	pos := uint32(0)
	for pos+frameHeaderV23 <= uint32(len(tagBody)) {
		if tagBody[pos] == 0x00 {
			break
		}
		frameID := string(tagBody[pos : pos+4])
		frameSize := binary.BigEndian.Uint32(tagBody[pos+4 : pos+8])
		if frameID == "TIT2" {
			foundTIT2 = true
		}
		pos += frameHeaderV23 + frameSize
	}
	if !foundTIT2 {
		t.Error("existing TIT2 frame was lost after injection")
	}
}

func TestMP3_WrongPassword(t *testing.T) {
	carrier := createTestMP3NoTag(t)

	var injected bytes.Buffer
	MP3Inject(bytes.NewReader(carrier), &injected, []byte("secret"), "correct")

	_, err := MP3Extract(bytes.NewReader(injected.Bytes()), "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestMP3_NoPayload(t *testing.T) {
	carrier := createTestMP3WithTag(t)

	_, err := MP3Extract(bytes.NewReader(carrier), "anypass")
	if err == nil {
		t.Fatal("expected error for MP3 without nightcloak data")
	}
}

func TestMP3_PaddingOptimization(t *testing.T) {
	carrier := createTestMP3WithTag(t) // has 2048 bytes padding
	origTagSize := decodeSyncsafe(carrier[6:10])

	// Small payload should fit in existing padding without expanding.
	var injected bytes.Buffer
	MP3Inject(bytes.NewReader(carrier), &injected, []byte("small"), "pass")

	result := injected.Bytes()
	newTagSize := decodeSyncsafe(result[6:10])

	if newTagSize != origTagSize {
		t.Errorf("tag size changed from %d to %d — padding should have been sufficient", origTagSize, newTagSize)
	}
}

func TestMP3_ReplaceExistingPayload(t *testing.T) {
	carrier := createTestMP3WithTag(t)

	// Inject first payload.
	var first bytes.Buffer
	MP3Inject(bytes.NewReader(carrier), &first, []byte("first"), "pass")

	// Inject second payload (should replace the first TXXX:ENCODEDBY).
	var second bytes.Buffer
	MP3Inject(bytes.NewReader(first.Bytes()), &second, []byte("second"), "pass")

	extracted, err := MP3Extract(bytes.NewReader(second.Bytes()), "pass")
	if err != nil {
		t.Fatalf("MP3Extract error: %v", err)
	}
	if string(extracted) != "second" {
		t.Errorf("expected 'second', got %q", extracted)
	}
}

func TestMP3_InvalidFile(t *testing.T) {
	notMP3 := []byte("this is not an MP3 file")

	_, err := MP3Extract(bytes.NewReader(notMP3), "pass")
	if err == nil {
		t.Fatal("expected error for non-MP3")
	}
}

func TestMP3_AudioDataIntact(t *testing.T) {
	audio := createTestMP3NoTag(t)

	var injected bytes.Buffer
	MP3Inject(bytes.NewReader(audio), &injected, []byte("payload"), "pass")

	result := injected.Bytes()
	tagSize := decodeSyncsafe(result[6:10])
	audioStart := id3HeaderSize + int(tagSize)

	// The audio data after the tag should be identical to the original.
	recoveredAudio := result[audioStart:]
	if !bytes.Equal(recoveredAudio, audio) {
		t.Error("audio data was modified during injection")
	}
}

// TestMP3_AudioStreamIntegrity proves that surgical padding injection is
// bit-perfect: the audio stream bytes are byte-for-byte identical before
// and after injection. This contrasts with ffmpeg which re-muxes the file,
// potentially touching audio data or rewriting existing tag fields.
func TestMP3_AudioStreamIntegrity(t *testing.T) {
	// Build an MP3 with two metadata frames (TIT2, TPE1) and 4KB padding,
	// followed by the audio data. The padding is large enough to absorb
	// our TXXX frame without requiring the tag to be expanded.

	// TIT2 frame: "Zero-Touch Verification"
	title := []byte("Zero-Touch Verification")
	tit2Data := make([]byte, 1+len(title))
	tit2Data[0] = 0x00 // ISO-8859-1
	copy(tit2Data[1:], title)
	tit2Frame := make([]byte, frameHeaderV23+len(tit2Data))
	copy(tit2Frame[0:4], "TIT2")
	binary.BigEndian.PutUint32(tit2Frame[4:8], uint32(len(tit2Data)))
	copy(tit2Frame[frameHeaderV23:], tit2Data)

	// TPE1 frame: "NightCloak"
	artist := []byte("NightCloak")
	tpe1Data := make([]byte, 1+len(artist))
	tpe1Data[0] = 0x00
	copy(tpe1Data[1:], artist)
	tpe1Frame := make([]byte, frameHeaderV23+len(tpe1Data))
	copy(tpe1Frame[0:4], "TPE1")
	binary.BigEndian.PutUint32(tpe1Frame[4:8], uint32(len(tpe1Data)))
	copy(tpe1Frame[frameHeaderV23:], tpe1Data)

	// 4KB padding — large enough that our TXXX frame fits without expansion.
	padding := make([]byte, 4096)

	tagBody := append(append(tit2Frame, tpe1Frame...), padding...)
	ss := encodeSyncsafe(uint32(len(tagBody)))
	id3Header := []byte{'I', 'D', '3', 0x03, 0x00, 0x00, ss[0], ss[1], ss[2], ss[3]}

	// 3 silent MPEG frames as audio data.
	audioFrame := make([]byte, 418)
	audioFrame[0] = 0xFF
	audioFrame[1] = 0xFB
	audioFrame[2] = 0x90
	audioFrame[3] = 0x04
	audioData := append(append(audioFrame, audioFrame...), audioFrame...)

	var carrier bytes.Buffer
	carrier.Write(id3Header)
	carrier.Write(tagBody)
	carrier.Write(audioData)
	original := carrier.Bytes()

	// Record the audio stream hash BEFORE injection.
	origTagSize := decodeSyncsafe(original[6:10])
	origAudioStart := id3HeaderSize + int(origTagSize)
	origAudioBytes := original[origAudioStart:]
	hashBefore := sha256.Sum256(origAudioBytes)

	// Inject a payload. Should fit in padding without shifting audio.
	payload := []byte("integrity-check-payload")
	var injected bytes.Buffer
	if err := MP3Inject(bytes.NewReader(original), &injected, payload, "integritypass"); err != nil {
		t.Fatalf("MP3Inject error: %v", err)
	}
	result := injected.Bytes()

	// Verify tag size did not change (padding was sufficient).
	newTagSize := decodeSyncsafe(result[6:10])
	if newTagSize != origTagSize {
		t.Errorf("tag expanded from %d to %d bytes — padding was insufficient for the test", origTagSize, newTagSize)
	}

	// Extract audio bytes from injected file.
	newAudioStart := id3HeaderSize + int(newTagSize)
	newAudioBytes := result[newAudioStart:]

	// SHA256 of audio stream must be identical.
	hashAfter := sha256.Sum256(newAudioBytes)
	if hashBefore != hashAfter {
		t.Errorf("audio stream SHA256 changed after injection\n  before: %x\n  after:  %x", hashBefore, hashAfter)
	}

	// Verify original metadata frames survive.
	tagBody2 := result[id3HeaderSize : id3HeaderSize+int(newTagSize)]
	pos := uint32(0)
	foundTIT2, foundTPE1 := false, false
	for pos+frameHeaderV23 <= uint32(len(tagBody2)) {
		if tagBody2[pos] == 0x00 {
			break
		}
		frameID := string(tagBody2[pos : pos+4])
		frameSize := binary.BigEndian.Uint32(tagBody2[pos+4 : pos+8])
		switch frameID {
		case "TIT2":
			foundTIT2 = true
			// Verify content is unchanged.
			frameContent := tagBody2[pos+frameHeaderV23+1 : pos+frameHeaderV23+frameSize]
			if string(frameContent) != string(title) {
				t.Errorf("TIT2 content changed: got %q, want %q", frameContent, title)
			}
		case "TPE1":
			foundTPE1 = true
			frameContent := tagBody2[pos+frameHeaderV23+1 : pos+frameHeaderV23+frameSize]
			if string(frameContent) != string(artist) {
				t.Errorf("TPE1 content changed: got %q, want %q", frameContent, artist)
			}
		}
		pos += uint32(frameHeaderV23) + frameSize
	}
	if !foundTIT2 {
		t.Error("TIT2 frame missing after injection")
	}
	if !foundTPE1 {
		t.Error("TPE1 frame missing after injection")
	}

	// Confirm payload is recoverable.
	extracted, err := MP3Extract(bytes.NewReader(result), "integritypass")
	if err != nil {
		t.Fatalf("MP3Extract error: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Errorf("payload mismatch: got %q, want %q", extracted, payload)
	}

	t.Logf("Audio stream SHA256 (before): %x", hashBefore)
	t.Logf("Audio stream SHA256 (after):  %x", hashAfter)
	t.Logf("Hashes match: %v", hashBefore == hashAfter)
}

func TestSyncsafe_RoundTrip(t *testing.T) {
	cases := []uint32{0, 1, 127, 128, 16383, 16384, 268435455}
	for _, v := range cases {
		encoded := encodeSyncsafe(v)
		decoded := decodeSyncsafe(encoded[:])
		if decoded != v {
			t.Errorf("syncsafe roundtrip failed for %d: encoded %v, decoded %d", v, encoded, decoded)
		}
		// Verify no byte has high bit set.
		for i, b := range encoded {
			if b&0x80 != 0 {
				t.Errorf("syncsafe byte %d has high bit set for value %d: %02x", i, v, b)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// PDF tests
// ---------------------------------------------------------------------------

// buildMinimalPDF constructs a valid flat-XREF PDF with three objects:
//   1: Catalog, 2: Pages (empty), 3: Info dict with /Title and optional /Keywords.
//
// Byte offsets are computed precisely so the XREF table is valid.
func buildMinimalPDF(keywords string) []byte {
	var body bytes.Buffer

	obj1 := "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
	obj2 := "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"

	var obj3 string
	if keywords != "" {
		obj3 = fmt.Sprintf("3 0 obj\n<< /Title (Test Document) /Keywords (%s) >>\nendobj\n", keywords)
	} else {
		obj3 = "3 0 obj\n<< /Title (Test Document) >>\nendobj\n"
	}

	header := "%PDF-1.4\n"
	body.WriteString(header)

	off1 := body.Len()
	body.WriteString(obj1)
	off2 := body.Len()
	body.WriteString(obj2)
	off3 := body.Len()
	body.WriteString(obj3)

	xrefOffset := body.Len()
	body.WriteString("xref\n")
	body.WriteString("0 4\n")
	body.WriteString("0000000000 65535 f\r\n")
	fmt.Fprintf(&body, "%010d 00000 n\r\n", off1)
	fmt.Fprintf(&body, "%010d 00000 n\r\n", off2)
	fmt.Fprintf(&body, "%010d 00000 n\r\n", off3)
	body.WriteString("trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R >>\n")
	fmt.Fprintf(&body, "startxref\n%d\n", xrefOffset)
	body.WriteString("%%EOF\n")

	return body.Bytes()
}

// TestPDF_HideReveal tests a full hide→reveal cycle on a minimal PDF.
func TestPDF_HideReveal(t *testing.T) {
	pdf := buildMinimalPDF("")
	payload := []byte("S:dGVzdC1wYXlsb2Fk") // "S:<base64(test-payload)>"

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, payload, "testpass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	recovered, err := PDFExtract(bytes.NewReader(out.Bytes()), "testpass")
	if err != nil {
		t.Fatalf("PDFExtract: %v", err)
	}
	if !bytes.Equal(recovered, payload) {
		t.Errorf("payload mismatch\n  got:  %q\n  want: %q", recovered, payload)
	}
}

// TestPDF_WrongPassword verifies extraction fails with the wrong password.
func TestPDF_WrongPassword(t *testing.T) {
	pdf := buildMinimalPDF("")

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, []byte("secret"), "correctpass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	_, err := PDFExtract(bytes.NewReader(out.Bytes()), "wrongpass")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

// TestPDF_SingleEOF verifies the output contains exactly one %%EOF marker.
// Multiple %%EOF markers are the forensic signature of incremental updates.
func TestPDF_SingleEOF(t *testing.T) {
	pdf := buildMinimalPDF("")

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, []byte("payload"), "pass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	result := out.Bytes()
	count := bytes.Count(result, []byte("%%EOF"))
	if count != 1 {
		t.Errorf("expected exactly 1 %%%%EOF marker, got %d", count)
	}
}

// TestPDF_NoPrevChain verifies the purge removes the /Prev key from the trailer.
func TestPDF_NoPrevChain(t *testing.T) {
	pdf := buildMinimalPDF("")

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, []byte("payload"), "pass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	if bytes.Contains(out.Bytes(), []byte("/Prev")) {
		t.Error("/Prev key found in purged output — incremental update history leaked")
	}
}

// TestPDF_ExistingKeywordsReplaced verifies that if /Keywords already exists
// in the Info dict, it is replaced (not duplicated) after injection.
func TestPDF_ExistingKeywordsReplaced(t *testing.T) {
	pdf := buildMinimalPDF("original keywords")

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, []byte("new-payload"), "pass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	result := out.Bytes()

	// The literal string "(original keywords)" must not appear in the output.
	if bytes.Contains(result, []byte("original keywords")) {
		t.Error("old /Keywords value still present after injection")
	}

	// There must be exactly one /Keywords entry.
	count := bytes.Count(result, []byte("/Keywords"))
	if count != 1 {
		t.Errorf("expected 1 /Keywords entry, got %d", count)
	}
}

// TestPDF_TitlePreserved verifies that other /Info fields survive injection.
func TestPDF_TitlePreserved(t *testing.T) {
	pdf := buildMinimalPDF("")

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, []byte("payload"), "pass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("/Title")) {
		t.Error("/Title key missing from Info dict after injection")
	}
	if !bytes.Contains(out.Bytes(), []byte("(Test Document)")) {
		t.Error("/Title value '(Test Document)' missing after injection")
	}
}

// TestPDF_IdempotentReveal verifies that injecting twice and revealing returns
// the second payload (not a corrupt concatenation of both).
func TestPDF_IdempotentReveal(t *testing.T) {
	pdf := buildMinimalPDF("")

	var first bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &first, []byte("first-payload"), "pass"); err != nil {
		t.Fatalf("first PDFInject: %v", err)
	}

	var second bytes.Buffer
	if err := PDFInject(bytes.NewReader(first.Bytes()), &second, []byte("second-payload"), "pass"); err != nil {
		t.Fatalf("second PDFInject: %v", err)
	}

	recovered, err := PDFExtract(bytes.NewReader(second.Bytes()), "pass")
	if err != nil {
		t.Fatalf("PDFExtract: %v", err)
	}
	if !bytes.Equal(recovered, []byte("second-payload")) {
		t.Errorf("expected second-payload, got %q", recovered)
	}
}

// TestPDF_ValidHeader verifies the output begins with the original PDF header.
func TestPDF_ValidHeader(t *testing.T) {
	pdf := buildMinimalPDF("")

	var out bytes.Buffer
	if err := PDFInject(bytes.NewReader(pdf), &out, []byte("payload"), "pass"); err != nil {
		t.Fatalf("PDFInject: %v", err)
	}

	if !bytes.HasPrefix(out.Bytes(), []byte("%PDF-1.4")) {
		t.Error("output does not begin with original PDF header")
	}
}

// TestPDF_NotAPDF verifies a meaningful error is returned for non-PDF input.
func TestPDF_NotAPDF(t *testing.T) {
	junk := []byte("this is not a PDF file at all")

	var out bytes.Buffer
	err := PDFInject(bytes.NewReader(junk), &out, []byte("payload"), "pass")
	if err == nil {
		t.Error("expected error for non-PDF input, got nil")
	}
}
