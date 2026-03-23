package nightmare

import (
	"encoding/base64"
	"strings"
)

// rot13_5 applies the ROT13+ROT5 substitution cipher.
//
// This is the core of Jiab77's "Base82" — it's actually Base64 output
// with a character substitution overlay that makes it look like a
// different encoding entirely. The mapping:
//
//	A-M → N-Z,  N-Z → A-M   (ROT13 on uppercase)
//	a-m → n-z,  n-z → a-m   (ROT13 on lowercase)
//	0-4 → 5-9,  5-9 → 0-4   (ROT5 on digits)
//
// The transformation is its own inverse: applying it twice returns
// the original string. This means encode and decode use the same function.
func rot13_5(b byte) byte {
	switch {
	case b >= 'A' && b <= 'Z':
		return 'A' + (b-'A'+13)%26
	case b >= 'a' && b <= 'z':
		return 'a' + (b-'a'+13)%26
	case b >= '0' && b <= '9':
		return '0' + (b-'0'+5)%10
	default:
		// Pass through non-alphanumeric chars (=, +, /) unchanged.
		// This preserves Base64 padding and structural characters.
		return b
	}
}

// Base82Encode encodes raw bytes using Jiab77's "Base82" scheme:
// standard Base64 encoding followed by ROT13+ROT5 character substitution.
func Base82Encode(data []byte) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(b64))
	for i := 0; i < len(b64); i++ {
		sb.WriteByte(rot13_5(b64[i]))
	}
	return sb.String()
}

// Base82Decode reverses the Base82 encoding: applies ROT13+ROT5
// (which is its own inverse) then standard Base64 decodes.
func Base82Decode(s string) ([]byte, error) {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		sb.WriteByte(rot13_5(s[i]))
	}
	return base64.StdEncoding.DecodeString(sb.String())
}
