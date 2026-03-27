package native

/*
Native PDF injection for flat XREF (ISO 32000, §7.5) PDFs.

Strategy: read the full file, parse the XREF chain (following /Prev links),
build a live object map (newest entry wins), inject the payload into the
/Keywords field of the /Info dictionary, then re-emit a clean single-pass
PDF — no /Prev chain, no ghost objects, single %%EOF.

Payload wire format inside /Keywords (hex string):
  <[16B sentinel][0x00 mode byte][payload bytes]>

The sentinel is HMAC-SHA256(password, "nightcloak")[:16], identical to the
PNG/JPEG/MP3 native paths. parseCOMPayload handles extraction.

Limitations (fall back to exiftool):
  - PDF 1.5+ cross-reference streams (compressed XREF objects)
  - Encrypted PDFs (/Encrypt key present in Trailer)
*/

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Exported sentinel errors so cloak.go can route to exiftool fallback.
var (
	ErrXREFStream   = errors.New("PDF uses XREF streams (PDF 1.5+): fall back to exiftool")
	ErrEncryptedPDF = errors.New("encrypted PDF: fall back to exiftool")
	ErrNoPDFPayload = errors.New("no nightcloak payload found in PDF")
)

type pdfXREFEntry struct {
	offset     int64
	generation int
	inUse      bool
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// PDFInject reads a PDF from r, injects payload into /Keywords of the /Info
// dictionary, and writes a forensically clean single-pass PDF to w.
func PDFInject(r io.Reader, w io.Writer, payload []byte, password string) error {
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

	// Build the blob: sentinel + mode byte + payload, stored as PDF hex string.
	sent := sentinel(password)
	blob := make([]byte, 0, sentinelSize+1+len(payload))
	blob = append(blob, sent...)
	blob = append(blob, 0x00) // single-segment mode (parseCOMPayload compatible)
	blob = append(blob, payload...)
	hexVal := "<" + strings.ToUpper(hex.EncodeToString(blob)) + ">"

	// Collect all live objects from the file.
	objects := extractLiveObjects(data, xref)

	// Inject into existing /Info or create a new one.
	infoRef, hasInfo := trailer["/Info"]
	if hasInfo {
		infoNum, err := parseObjRef(infoRef)
		if err != nil {
			return fmt.Errorf("invalid /Info ref %q: %w", infoRef, err)
		}
		orig, ok := objects[infoNum]
		if !ok {
			return fmt.Errorf("Info object %d not found in live object set", infoNum)
		}
		objects[infoNum] = injectDictKey(orig, "/Keywords", hexVal)
	} else {
		// Allocate next free object number.
		newNum := 1
		for num := range objects {
			if num >= newNum {
				newNum = num + 1
			}
		}
		objects[newNum] = []byte(fmt.Sprintf(
			"%d 0 obj\n<< /Keywords %s >>\nendobj\n", newNum, hexVal,
		))
		trailer["/Info"] = fmt.Sprintf("%d 0 R", newNum)
		if szStr, ok := trailer["/Size"]; ok {
			existing, _ := strconv.Atoi(strings.TrimSpace(szStr))
			if newNum >= existing {
				trailer["/Size"] = strconv.Itoa(newNum + 1)
			}
		}
	}

	return writePurgedPDF(w, data, objects, trailer)
}

// PDFExtract reads a PDF from r and returns the payload hidden in /Keywords
// if the HMAC sentinel matches the given password.
func PDFExtract(r io.Reader, password string) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading PDF: %w", err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, errors.New("not a valid PDF file")
	}

	xref, trailer, err := parseXREFChain(data)
	if err != nil {
		return nil, err
	}

	infoRef, ok := trailer["/Info"]
	if !ok {
		return nil, ErrNoPDFPayload
	}
	infoNum, err := parseObjRef(infoRef)
	if err != nil {
		return nil, ErrNoPDFPayload
	}
	entry, ok := xref[infoNum]
	if !ok || !entry.inUse {
		return nil, ErrNoPDFPayload
	}

	objBytes, err := extractObjectAt(data, entry.offset)
	if err != nil {
		return nil, ErrNoPDFPayload
	}

	kwVal := getDictStringValue(objBytes, "/Keywords")
	if kwVal == "" {
		return nil, ErrNoPDFPayload
	}

	// Decode the PDF string value (hex <...> or literal (...)).
	var raw []byte
	if strings.HasPrefix(kwVal, "<") && strings.HasSuffix(kwVal, ">") {
		inner := strings.TrimSpace(kwVal[1 : len(kwVal)-1])
		raw, err = hex.DecodeString(inner)
		if err != nil {
			return nil, ErrNoPDFPayload
		}
	} else if strings.HasPrefix(kwVal, "(") && strings.HasSuffix(kwVal, ")") {
		raw = []byte(kwVal[1 : len(kwVal)-1])
	} else {
		return nil, ErrNoPDFPayload
	}

	expected := sentinel(password)
	result, _, _, err := parseCOMPayload(raw, expected)
	if err != nil {
		return nil, ErrNoPDFPayload
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// XREF chain parser
// ---------------------------------------------------------------------------

// parseXREFChain follows the /Prev chain (newest → oldest) and returns a
// merged object map (newest definition wins) and the newest trailer fields.
func parseXREFChain(data []byte) (map[int]pdfXREFEntry, map[string]string, error) {
	offset, err := findStartXREF(data)
	if err != nil {
		return nil, nil, err
	}

	xref := make(map[int]pdfXREFEntry)
	var trailer map[string]string
	first := true

	for offset > 0 {
		sect, fields, prev, err := parseXREFTable(data, int(offset))
		if err != nil {
			return nil, nil, err
		}
		// Newer entries take precedence.
		for num, entry := range sect {
			if _, exists := xref[num]; !exists {
				xref[num] = entry
			}
		}
		if first {
			trailer = fields
			first = false
		}
		offset = prev
	}

	return xref, trailer, nil
}

// findStartXREF searches the last 1KB of the file for the last "startxref"
// keyword and returns the integer offset value that follows it.
func findStartXREF(data []byte) (int64, error) {
	tail := data
	base := 0
	if len(data) > 1024 {
		base = len(data) - 1024
		tail = data[base:]
	}

	idx := bytes.LastIndex(tail, []byte("startxref"))
	if idx < 0 {
		return 0, errors.New("'startxref' keyword not found")
	}

	after := tail[idx+len("startxref"):]
	i := 0
	for i < len(after) && pdfIsWS(after[i]) {
		i++
	}
	j := i
	for j < len(after) && !pdfIsWS(after[j]) {
		j++
	}
	if i == j {
		return 0, errors.New("startxref has no value")
	}
	n, err := strconv.ParseInt(string(after[i:j]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("startxref value: %w", err)
	}
	return n, nil
}

// parseXREFTable parses one flat xref section + trailer dict at the given
// byte offset in data. Returns: entries, trailer fields, /Prev offset, error.
func parseXREFTable(data []byte, offset int) (map[int]pdfXREFEntry, map[string]string, int64, error) {
	if offset < 0 || offset >= len(data) {
		return nil, nil, 0, fmt.Errorf("xref offset %d out of bounds (file length %d)", offset, len(data))
	}

	pos := offset
	// Skip leading whitespace.
	for pos < len(data) && pdfIsWS(data[pos]) {
		pos++
	}

	// Detect cross-reference streams (PDF 1.5+): the object at startxref
	// begins with "<num> <num> obj" rather than "xref".
	if pos < len(data) && data[pos] != 'x' {
		return nil, nil, 0, ErrXREFStream
	}
	if !bytes.HasPrefix(data[pos:], []byte("xref")) {
		return nil, nil, 0, ErrXREFStream
	}
	pos += 4

	// Skip whitespace after "xref".
	for pos < len(data) && pdfIsWS(data[pos]) {
		pos++
	}

	xref := make(map[int]pdfXREFEntry)

	// Parse subsections until "trailer".
	for pos < len(data) {
		if bytes.HasPrefix(data[pos:], []byte("trailer")) {
			break
		}

		// Subsection header: "<firstObj> <count>\n".
		eol := bytes.IndexAny(data[pos:], "\r\n")
		if eol < 0 {
			break
		}
		line := strings.TrimSpace(string(data[pos : pos+eol]))
		pos += eol
		for pos < len(data) && (data[pos] == '\r' || data[pos] == '\n') {
			pos++
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			break
		}
		firstObj, err := strconv.Atoi(parts[0])
		if err != nil {
			break
		}
		count, err := strconv.Atoi(parts[1])
		if err != nil {
			break
		}

		// Each XREF entry is exactly 20 bytes per ISO 32000 §7.5.4.
		for i := 0; i < count; i++ {
			if pos+20 > len(data) {
				return nil, nil, 0, errors.New("truncated xref table entry")
			}
			entry := data[pos : pos+20]
			pos += 20

			offStr := strings.TrimSpace(string(entry[0:10]))
			genStr := strings.TrimSpace(string(entry[11:16]))
			status := entry[17] // 'n' = in-use, 'f' = free

			off, err := strconv.ParseInt(offStr, 10, 64)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("xref entry offset: %w", err)
			}
			gen, err := strconv.Atoi(genStr)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("xref entry generation: %w", err)
			}

			xref[firstObj+i] = pdfXREFEntry{
				offset:     off,
				generation: gen,
				inUse:      status == 'n',
			}
		}
	}

	// Find and parse the trailer dictionary.
	tIdx := bytes.Index(data[pos:], []byte("trailer"))
	if tIdx < 0 {
		return nil, nil, 0, errors.New("'trailer' keyword not found after xref table")
	}
	pos += tIdx + len("trailer")

	for pos < len(data) && pdfIsWS(data[pos]) {
		pos++
	}
	if pos+1 >= len(data) || data[pos] != '<' || data[pos+1] != '<' {
		return nil, nil, 0, errors.New("expected '<<' after trailer keyword")
	}

	dictEnd, err := pdfSkipDict(data, pos)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("parsing trailer dict: %w", err)
	}
	fields := pdfParseDict(data[pos:dictEnd])

	var prev int64
	if prevStr, ok := fields["/Prev"]; ok {
		prev, _ = strconv.ParseInt(strings.TrimSpace(prevStr), 10, 64)
	}

	return xref, fields, prev, nil
}

// ---------------------------------------------------------------------------
// Object extraction
// ---------------------------------------------------------------------------

// extractObjectAt extracts the bytes of a PDF object starting at the given
// offset. Returns from "<N> <G> obj" through "endobj" inclusive.
func extractObjectAt(data []byte, offset int64) ([]byte, error) {
	pos := int(offset)
	if pos < 0 || pos >= len(data) {
		return nil, fmt.Errorf("object offset %d out of bounds", offset)
	}

	// Find "obj" keyword (skip past "<N> <G> obj").
	objMarker := bytes.Index(data[pos:], []byte(" obj"))
	if objMarker < 0 {
		return nil, fmt.Errorf("'obj' keyword not found at offset %d", offset)
	}
	bodyStart := pos + objMarker + 4

	endMarker := bytes.Index(data[bodyStart:], []byte("endobj"))
	if endMarker < 0 {
		return nil, fmt.Errorf("'endobj' not found for object at offset %d", offset)
	}
	endPos := bodyStart + endMarker + len("endobj")

	return data[pos:endPos], nil
}

// extractLiveObjects returns a map of object number → raw object bytes for
// all in-use objects in the xref map.
func extractLiveObjects(data []byte, xref map[int]pdfXREFEntry) map[int][]byte {
	objects := make(map[int][]byte, len(xref))
	for num, entry := range xref {
		if !entry.inUse || num == 0 || entry.offset <= 0 {
			continue
		}
		obj, err := extractObjectAt(data, entry.offset)
		if err != nil {
			continue
		}
		objects[num] = obj
	}
	return objects
}

// ---------------------------------------------------------------------------
// Dict manipulation
// ---------------------------------------------------------------------------

// getDictStringValue finds key in the first dict (<<...>>) of objBytes and
// returns the raw value token (e.g. "<HEXHEX>", "(literal)", "/Name").
func getDictStringValue(objBytes []byte, key string) string {
	dictStart := bytes.Index(objBytes, []byte("<<"))
	if dictStart < 0 {
		return ""
	}
	dictEnd, err := pdfSkipDict(objBytes, dictStart)
	if err != nil {
		return ""
	}
	fields := pdfParseDict(objBytes[dictStart:dictEnd])
	return fields[key]
}

// injectDictKey returns a copy of objBytes with key set to newValue inside
// the first dict. Replaces an existing value or inserts before closing ">>".
func injectDictKey(objBytes []byte, key, newValue string) []byte {
	dictStart := bytes.Index(objBytes, []byte("<<"))
	if dictStart < 0 {
		return objBytes
	}
	dictEnd, err := pdfSkipDict(objBytes, dictStart)
	if err != nil {
		return objBytes
	}
	inner := objBytes[dictStart:dictEnd] // includes << and >>

	// Locate the key inside the dict.
	keyPos := pdfFindKey(inner, key)
	if keyPos >= 0 {
		// Advance past the key name.
		valStart := keyPos + len(key)
		for valStart < len(inner) && pdfIsWS(inner[valStart]) {
			valStart++
		}
		valEnd, err := pdfSkipValue(inner, valStart)
		if err == nil && valEnd > valStart {
			var out bytes.Buffer
			out.Write(objBytes[:dictStart+keyPos+len(key)])
			out.WriteByte(' ')
			out.WriteString(newValue)
			out.Write(inner[valEnd : len(inner)-2]) // content after old value, before >>
			out.WriteString(">>")
			out.Write(objBytes[dictEnd:])
			return out.Bytes()
		}
	}

	// Key not found — insert before closing ">>".
	closePos := dictStart + len(inner) - 2
	var out bytes.Buffer
	out.Write(objBytes[:closePos])
	out.WriteString("\n" + key + " " + newValue + "\n")
	out.WriteString(">>")
	out.Write(objBytes[dictEnd:])
	return out.Bytes()
}

// pdfFindKey returns the byte index of key within inner (a dict including << >>),
// or -1 if not found. Requires that the key be preceded by whitespace or '<<'.
func pdfFindKey(inner []byte, key string) int {
	kb := []byte(key)
	for i := 0; i <= len(inner)-len(kb); i++ {
		if !bytes.Equal(inner[i:i+len(kb)], kb) {
			continue
		}
		// Must be preceded by whitespace, '<<', or start of inner.
		if i > 0 && !pdfIsWS(inner[i-1]) && inner[i-1] != '<' {
			continue
		}
		// Must be followed by whitespace or value-start character.
		after := i + len(kb)
		if after < len(inner) {
			next := inner[after]
			if !pdfIsWS(next) && next != '(' && next != '<' && next != '/' && next != '[' {
				continue
			}
		}
		return i
	}
	return -1
}

// ---------------------------------------------------------------------------
// PDF syntax helpers
// ---------------------------------------------------------------------------

func pdfIsWS(b byte) bool {
	return b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20
}

// pdfSkipDict finds the matching ">>" for the "<<" at pos, handling nesting,
// literal strings, and hex strings. Returns position after closing ">>".
func pdfSkipDict(data []byte, pos int) (int, error) {
	if pos+1 >= len(data) || data[pos] != '<' || data[pos+1] != '<' {
		return 0, errors.New("expected '<<'")
	}
	pos += 2
	depth := 1
	for pos < len(data) {
		switch {
		case pos+1 < len(data) && data[pos] == '<' && data[pos+1] == '<':
			depth++
			pos += 2
		case pos+1 < len(data) && data[pos] == '>' && data[pos+1] == '>':
			depth--
			pos += 2
			if depth == 0 {
				return pos, nil
			}
		case data[pos] == '(':
			var err error
			pos, err = pdfSkipLiteralString(data, pos)
			if err != nil {
				return 0, err
			}
		case data[pos] == '<':
			// Hex string <...> — not a dict opener.
			end := bytes.IndexByte(data[pos+1:], '>')
			if end < 0 {
				return 0, errors.New("unterminated hex string in dict")
			}
			pos += end + 2
		default:
			pos++
		}
	}
	return 0, errors.New("unterminated dict")
}

// pdfSkipLiteralString skips a PDF literal string starting with '(' at pos.
func pdfSkipLiteralString(data []byte, pos int) (int, error) {
	if pos >= len(data) || data[pos] != '(' {
		return pos, errors.New("expected '('")
	}
	pos++
	depth := 1
	for pos < len(data) {
		switch data[pos] {
		case '\\':
			pos += 2
		case '(':
			depth++
			pos++
		case ')':
			depth--
			pos++
			if depth == 0 {
				return pos, nil
			}
		default:
			pos++
		}
	}
	return 0, errors.New("unterminated literal string")
}

// pdfSkipValue returns the end index (exclusive) of the PDF value starting at pos.
func pdfSkipValue(data []byte, pos int) (int, error) {
	if pos >= len(data) {
		return pos, errors.New("empty value")
	}
	switch data[pos] {
	case '(':
		return pdfSkipLiteralString(data, pos)
	case '<':
		if pos+1 < len(data) && data[pos+1] == '<' {
			return pdfSkipDict(data, pos)
		}
		end := bytes.IndexByte(data[pos+1:], '>')
		if end < 0 {
			return 0, errors.New("unterminated hex string")
		}
		return pos + 1 + end + 1, nil
	case '[':
		depth := 1
		i := pos + 1
		for i < len(data) {
			switch data[i] {
			case '[':
				depth++
				i++
			case ']':
				depth--
				i++
				if depth == 0 {
					return i, nil
				}
			case '(':
				var err error
				i, err = pdfSkipLiteralString(data, i)
				if err != nil {
					return 0, err
				}
			default:
				i++
			}
		}
		return 0, errors.New("unterminated array")
	default:
		// Number, name (/Foo), boolean, or indirect reference (N G R).
		end := pos
		for end < len(data) && !pdfIsWS(data[end]) && data[end] != '/' && data[end] != '<' && data[end] != '(' && data[end] != '[' && data[end] != ']' && data[end] != '>' {
			end++
		}
		// Check for object reference "N G R".
		ws1 := end
		for ws1 < len(data) && pdfIsWS(data[ws1]) {
			ws1++
		}
		if ws1 < len(data) && data[ws1] >= '0' && data[ws1] <= '9' {
			genEnd := ws1
			for genEnd < len(data) && !pdfIsWS(data[genEnd]) {
				genEnd++
			}
			ws2 := genEnd
			for ws2 < len(data) && pdfIsWS(data[ws2]) {
				ws2++
			}
			if ws2 < len(data) && data[ws2] == 'R' {
				return ws2 + 1, nil
			}
		}
		return end, nil
	}
}

// pdfParseDict parses a PDF dict (including << >>) and returns key → raw value pairs.
// Values are raw token strings (e.g. "1 0 R", "4", "(title)", "<hex>", "/Name").
func pdfParseDict(data []byte) map[string]string {
	result := make(map[string]string)

	start := bytes.Index(data, []byte("<<"))
	if start < 0 {
		return result
	}
	end, err := pdfSkipDict(data, start)
	if err != nil {
		return result
	}

	pos := start + 2
	limit := end - 2

	for pos < limit {
		for pos < limit && pdfIsWS(data[pos]) {
			pos++
		}
		if pos >= limit {
			break
		}
		if data[pos] != '/' {
			// Skip unexpected token.
			pos++
			continue
		}

		keyStart := pos
		pos++
		for pos < limit && !pdfIsWS(data[pos]) && data[pos] != '/' && data[pos] != '<' && data[pos] != '(' && data[pos] != '[' {
			pos++
		}
		key := string(data[keyStart:pos])

		for pos < limit && pdfIsWS(data[pos]) {
			pos++
		}
		if pos >= limit {
			result[key] = ""
			break
		}

		valEnd, err := pdfSkipValue(data[pos:], 0)
		if err != nil {
			break
		}
		result[key] = string(data[pos : pos+valEnd])
		pos += valEnd
	}

	return result
}

// parseObjRef parses "N G R" or just "N" and returns the object number.
func parseObjRef(ref string) (int, error) {
	parts := strings.Fields(ref)
	if len(parts) == 0 {
		return 0, errors.New("empty object reference")
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("object number in %q: %w", ref, err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Purge writer
// ---------------------------------------------------------------------------

// writePurgedPDF emits a clean single-pass PDF: header, live objects (new
// offsets), flat XREF table, trailer without /Prev, single %%EOF.
func writePurgedPDF(w io.Writer, origData []byte, objects map[int][]byte, trailer map[string]string) error {
	var buf bytes.Buffer

	// Preserve the original %PDF-x.y header line.
	headerEnd := bytes.IndexByte(origData, '\n')
	if headerEnd < 0 {
		headerEnd = 8
	}
	buf.Write(origData[:headerEnd+1])

	// Binary comment: 4 bytes with high bit set signals binary content to
	// mailers and transfer agents (PDF/A recommendation).
	buf.WriteString("%\xe2\xe3\xcf\xd3\n")

	// Write live objects in sorted order, recording each byte offset.
	objNums := make([]int, 0, len(objects))
	for num := range objects {
		objNums = append(objNums, num)
	}
	sort.Ints(objNums)

	offsets := make(map[int]int64, len(objects))
	for _, num := range objNums {
		offsets[num] = int64(buf.Len())
		obj := objects[num]
		buf.Write(obj)
		if len(obj) == 0 || obj[len(obj)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}

	// XREF table — single subsection covering objects 0..maxNum.
	xrefOffset := int64(buf.Len())
	maxNum := 0
	for _, n := range objNums {
		if n > maxNum {
			maxNum = n
		}
	}
	total := maxNum + 1

	buf.WriteString("xref\n")
	buf.WriteString(fmt.Sprintf("0 %d\n", total))

	// Object 0: permanent free list head.
	// Each entry is exactly 20 bytes: 10B offset + SP + 5B gen + SP + status + CR LF.
	buf.WriteString("0000000000 65535 f\r\n")

	for i := 1; i <= maxNum; i++ {
		if off, ok := offsets[i]; ok {
			fmt.Fprintf(&buf, "%010d 00000 n\r\n", off)
		} else {
			buf.WriteString("0000000000 00000 f\r\n")
		}
	}

	// Trailer — no /Prev, updated /Size.
	buf.WriteString("trailer\n<<\n")
	buf.WriteString("/Size " + strconv.Itoa(total) + "\n")
	for _, k := range []string{"/Root", "/Info"} {
		if v, ok := trailer[k]; ok {
			buf.WriteString(k + " " + v + "\n")
		}
	}
	// Preserve any other trailer keys except /Prev, /Size, /Root, /Info.
	skip := map[string]bool{"/Prev": true, "/Size": true, "/Root": true, "/Info": true}
	for k, v := range trailer {
		if !skip[k] {
			buf.WriteString(k + " " + v + "\n")
		}
	}
	buf.WriteString(">>\n")
	fmt.Fprintf(&buf, "startxref\n%d\n", xrefOffset)
	buf.WriteString("%%EOF\n")

	_, err := w.Write(buf.Bytes())
	return err
}
