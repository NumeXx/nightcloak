package nightmare

import (
	"encoding/hex"
	"fmt"
)

/*
Nightmarify obfuscates a string through the nightmare chain:

  input -> hex encode -> Base82 encode (Base64 + ROT13/5)

The result looks like Base64 but fails every Base64 decoder. An analyst
sees familiar-looking encoding but cannot decode it with any standard tool.
*/
func Nightmarify(input string) string {
	hexStr := hex.EncodeToString([]byte(input))
	return Base82Encode([]byte(hexStr))
}

/*
Dreamify reverses the nightmare chain:

  input -> Base82 decode -> hex decode -> original string
*/
func Dreamify(input string) (string, error) {
	hexBytes, err := Base82Decode(input)
	if err != nil {
		return "", fmt.Errorf("base82 decode failed: %w", err)
	}

	raw, err := hex.DecodeString(string(hexBytes))
	if err != nil {
		return "", fmt.Errorf("hex decode failed: %w", err)
	}

	return string(raw), nil
}

// NightmarifyBytes obfuscates raw bytes (for file payloads).
func NightmarifyBytes(data []byte) string {
	hexStr := hex.EncodeToString(data)
	return Base82Encode([]byte(hexStr))
}

// DreamifyBytes reverses obfuscation back to raw bytes.
func DreamifyBytes(input string) ([]byte, error) {
	hexBytes, err := Base82Decode(input)
	if err != nil {
		return nil, fmt.Errorf("base82 decode failed: %w", err)
	}

	raw, err := hex.DecodeString(string(hexBytes))
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}

	return raw, nil
}
