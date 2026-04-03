package native

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PNGWipe streams a PNG from r to w, removing the nightcloak tEXt chunk
// identified by the password-derived sentinel. All other chunks pass through
// verbatim. Returns an error if no matching payload is found.
func PNGWipe(r io.Reader, w io.Writer, password string) error {
	sig := make([]byte, 8)
	if _, err := io.ReadFull(r, sig); err != nil {
		return fmt.Errorf("reading PNG signature: %w", err)
	}
	if !bytes.Equal(sig, pngSignature) {
		return errors.New("not a valid PNG file")
	}
	if _, err := w.Write(sig); err != nil {
		return err
	}

	expectedSentinel := sentinel(password)
	header := make([]byte, chunkHeaderSize)
	found := false

	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return fmt.Errorf("reading chunk header: %w", err)
		}
		chunkLen := binary.BigEndian.Uint32(header[0:4])
		chunkType := string(header[4:8])

		if chunkType == iendType {
			if !found {
				return errors.New("no nightcloak payload found in PNG")
			}
			if _, err := w.Write(header); err != nil {
				return err
			}
			crcBuf := make([]byte, chunkCRCSize)
			if _, err := io.ReadFull(r, crcBuf); err != nil {
				return fmt.Errorf("reading IEND CRC: %w", err)
			}
			_, err := w.Write(crcBuf)
			return err
		}

		if chunkType == textType {
			chunkData := make([]byte, chunkLen)
			if _, err := io.ReadFull(r, chunkData); err != nil {
				return fmt.Errorf("reading tEXt data: %w", err)
			}
			crcBuf := make([]byte, chunkCRCSize)
			if _, err := io.ReadFull(r, crcBuf); err != nil {
				return fmt.Errorf("reading tEXt CRC: %w", err)
			}

			nullIdx := bytes.IndexByte(chunkData, 0x00)
			if nullIdx >= 0 {
				value := chunkData[nullIdx+1:]
				if len(value) >= sentinelSize && hmac.Equal(value[:sentinelSize], expectedSentinel) {
					found = true
					continue // drop this chunk
				}
			}

			// Not ours, copy through.
			if _, err := w.Write(header); err != nil {
				return err
			}
			if _, err := w.Write(chunkData); err != nil {
				return err
			}
			if _, err := w.Write(crcBuf); err != nil {
				return err
			}
			continue
		}

		// Any other chunk: pass through verbatim.
		if _, err := w.Write(header); err != nil {
			return err
		}
		if _, err := io.CopyN(w, r, int64(chunkLen)+chunkCRCSize); err != nil {
			return fmt.Errorf("copying chunk %s: %w", chunkType, err)
		}
	}
}

// JPEGExifWipe streams a JPEG from r to w, removing any APP1/EXIF segment
// whose UserComment sentinel matches the given password. All other segments
// pass through verbatim.
func JPEGExifWipe(r io.Reader, w io.Writer, password string) error {
	var soi [2]byte
	if _, err := io.ReadFull(r, soi[:]); err != nil {
		return fmt.Errorf("reading SOI: %w", err)
	}
	if binary.BigEndian.Uint16(soi[:]) != markerSOI {
		return errors.New("not a valid JPEG file")
	}
	if _, err := w.Write(soi[:]); err != nil {
		return err
	}

	expectedSentinel := sentinel(password)
	found := false

	var marker [2]byte
	for {
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			return fmt.Errorf("reading marker: %w", err)
		}
		m := binary.BigEndian.Uint16(marker[:])

		if m == markerSOS {
			if !found {
				return errors.New("no nightcloak payload found in JPEG EXIF")
			}
			if _, err := w.Write(marker[:]); err != nil {
				return err
			}
			_, err := io.Copy(w, r)
			return err
		}

		if isStandaloneMarker(m) {
			if _, err := w.Write(marker[:]); err != nil {
				return err
			}
			continue
		}

		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return fmt.Errorf("reading segment length: %w", err)
		}
		segLen := binary.BigEndian.Uint16(lenBuf[:])
		if segLen < 2 {
			return fmt.Errorf("invalid segment length %d", segLen)
		}
		dataLen := int(segLen - 2)

		data := make([]byte, dataLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return fmt.Errorf("reading segment data: %w", err)
		}

		// Check if this APP1 is ours.
		if m == markerAPP1 && dataLen > exifIdSize && string(data[:exifIdSize]) == "Exif\x00\x00" {
			userComment := extractUserComment(data[exifIdSize:])
			if userComment != nil && len(userComment) >= userCommentCharsetSize+sentinelSize {
				commentData := userComment[userCommentCharsetSize:]
				if hmac.Equal(commentData[:sentinelSize], expectedSentinel) {
					found = true
					continue // drop this segment
				}
			}
		}

		// Not ours, copy through.
		if _, err := w.Write(marker[:]); err != nil {
			return err
		}
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
}

// MP3Wipe removes the nightcloak TXXX:ENCODEDBY frame from the ID3v2 tag
// and streams the audio data through unchanged.
func MP3Wipe(r io.Reader, w io.Writer, password string) error {
	header := make([]byte, id3HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	if string(header[0:3]) != "ID3" {
		return errors.New("no ID3v2 tag found in MP3")
	}

	version := header[3]
	flags := header[5]
	tagSize := decodeSyncsafe(header[6:10])

	tagBody := make([]byte, tagSize)
	if _, err := io.ReadFull(r, tagBody); err != nil {
		return fmt.Errorf("reading tag body: %w", err)
	}

	frameStart := uint32(0)
	if flags&0x40 != 0 {
		if len(tagBody) < 4 {
			return errors.New("truncated extended header")
		}
		var extSize uint32
		if version == 4 {
			extSize = decodeSyncsafe(tagBody[0:4])
		} else {
			extSize = binary.BigEndian.Uint32(tagBody[0:4])
		}
		frameStart = extSize
	}

	framesEnd := findFramesEnd(tagBody, frameStart, version)
	originalEnd := framesEnd
	tagBody, framesEnd = removeTXXXFrame(tagBody, frameStart, framesEnd, version, txDescription)

	if framesEnd == originalEnd {
		return errors.New("no nightcloak payload found in MP3")
	}

	// Write updated header with new tag size.
	newTagSize := framesEnd + defaultPadding
	ss := encodeSyncsafe(newTagSize)
	newHeader := make([]byte, id3HeaderSize)
	copy(newHeader, header)
	copy(newHeader[6:10], ss[:])

	if _, err := w.Write(newHeader); err != nil {
		return err
	}
	if _, err := w.Write(tagBody[:framesEnd]); err != nil {
		return err
	}
	padding := make([]byte, defaultPadding)
	if _, err := w.Write(padding); err != nil {
		return err
	}

	_, err := io.Copy(w, r)
	return err
}

// PDFWipe re-emits a clean purged PDF with the /Keywords field removed from
// the /Info dictionary, erasing the nightcloak payload entirely.
func PDFWipe(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading PDF: %w", err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return errors.New("not a valid PDF file")
	}

	xref, trailer, err := parseXREFChain(data)
	if err != nil {
		return err
	}
	if _, ok := trailer["/Encrypt"]; ok {
		return ErrEncryptedPDF
	}

	infoRef, hasInfo := trailer["/Info"]
	if !hasInfo {
		return ErrNoPDFPayload
	}
	infoNum, err := parseObjRef(infoRef)
	if err != nil {
		return ErrNoPDFPayload
	}

	objects := extractLiveObjects(data, xref)

	orig, ok := objects[infoNum]
	if !ok {
		return ErrNoPDFPayload
	}

	// Verify there's actually a /Keywords to remove.
	if getDictStringValue(orig, "/Keywords") == "" {
		return ErrNoPDFPayload
	}

	objects[infoNum] = removeDictKey(orig, "/Keywords")

	return writePurgedPDF(w, data, objects, trailer)
}

// removeDictKey returns a copy of objBytes with key stripped from the first
// dict. If the key is not found, objBytes is returned unchanged.
func removeDictKey(objBytes []byte, key string) []byte {
	dictStart := bytes.Index(objBytes, []byte("<<"))
	if dictStart < 0 {
		return objBytes
	}
	dictEnd, err := pdfSkipDict(objBytes, dictStart)
	if err != nil {
		return objBytes
	}
	inner := objBytes[dictStart:dictEnd]

	keyPos := pdfFindKey(inner, key)
	if keyPos < 0 {
		return objBytes
	}

	// Find the end of the value.
	valStart := keyPos + len(key)
	for valStart < len(inner) && pdfIsWS(inner[valStart]) {
		valStart++
	}
	valEnd, err := pdfSkipValue(inner, valStart)
	if err != nil {
		return objBytes
	}

	var out bytes.Buffer
	out.Write(objBytes[:dictStart+keyPos])
	out.Write(inner[valEnd : len(inner)-2]) // skip key+value, keep rest before >>
	out.WriteString(">>")
	out.Write(objBytes[dictEnd:])
	return out.Bytes()
}
