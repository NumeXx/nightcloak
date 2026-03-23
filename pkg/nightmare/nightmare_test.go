package nightmare

import (
	"strings"
	"testing"
)

// --- Base82 (ROT13/5) tests ---

func TestRot13_5_SelfInverse(t *testing.T) {
	// ROT13/5 applied twice must return the original byte.
	for b := byte(0); b < 128; b++ {
		if rot13_5(rot13_5(b)) != b {
			t.Errorf("rot13_5 is not self-inverse for byte %d (%c)", b, b)
		}
	}
}

func TestRot13_5_KnownMappings(t *testing.T) {
	// Verify the exact tr 'A-Za-z0-9' 'N-ZA-Mn-za-m5-90-4' mapping.
	cases := []struct {
		in, out byte
	}{
		{'A', 'N'}, {'M', 'Z'}, {'N', 'A'}, {'Z', 'M'},
		{'a', 'n'}, {'m', 'z'}, {'n', 'a'}, {'z', 'm'},
		{'0', '5'}, {'4', '9'}, {'5', '0'}, {'9', '4'},
		{'=', '='}, {'+', '+'}, {'/', '/'},
	}
	for _, tc := range cases {
		got := rot13_5(tc.in)
		if got != tc.out {
			t.Errorf("rot13_5(%c) = %c, want %c", tc.in, got, tc.out)
		}
	}
}

func TestBase82_RoundTrip(t *testing.T) {
	inputs := []string{
		"",
		"A",
		"Hello, World!",
		"test123",
		string([]byte{0x00, 0xFF, 0x80, 0x7F}),
	}
	for _, input := range inputs {
		encoded := Base82Encode([]byte(input))
		decoded, err := Base82Decode(encoded)
		if err != nil {
			t.Errorf("Base82Decode(%q) error: %v", encoded, err)
			continue
		}
		if string(decoded) != input {
			t.Errorf("roundtrip failed for %q: got %q", input, string(decoded))
		}
	}
}

func TestBase82Encode_NotStandardBase64(t *testing.T) {
	input := []byte("The quick brown fox jumps over the lazy dog")
	encoded := Base82Encode(input)

	// The output must NOT be valid standard Base64 that decodes to the input.
	// (It might accidentally be valid base64 for some inputs, but should
	// decode to garbage, not the original.)
	if encoded == "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==" {
		t.Error("Base82 output is identical to standard Base64 — ROT13/5 not applied")
	}
}

// --- Nightmare chain tests ---

func TestNightmarify_Dreamify_RoundTrip(t *testing.T) {
	inputs := []string{
		"hello",
		"",
		"The quick brown fox",
		"nightcloak v0.1.0",
		"special chars: !@#$%^&*()",
		"unicode: 你好世界 🌍",
		strings.Repeat("A", 1000),
	}
	for _, input := range inputs {
		obfuscated := Nightmarify(input)
		restored, err := Dreamify(obfuscated)
		if err != nil {
			t.Errorf("Dreamify error for input %q: %v", input, err)
			continue
		}
		if restored != input {
			t.Errorf("Dreamify(Nightmarify(%q)) = %q", input, restored)
		}
	}
}

func TestNightmarifyBytes_DreamifyBytes_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		[]byte("binary payload"),
		make([]byte, 256), // all zeros
	}
	for i, input := range inputs {
		obfuscated := NightmarifyBytes(input)
		restored, err := DreamifyBytes(obfuscated)
		if err != nil {
			t.Errorf("DreamifyBytes error for case %d: %v", i, err)
			continue
		}
		if len(restored) != len(input) {
			t.Errorf("case %d: length mismatch %d vs %d", i, len(restored), len(input))
			continue
		}
		for j := range input {
			if restored[j] != input[j] {
				t.Errorf("case %d: byte %d differs: got %02x want %02x", i, j, restored[j], input[j])
				break
			}
		}
	}
}

func TestNightmarify_OutputIsNotBase64Decodable(t *testing.T) {
	input := "secret message"
	obfuscated := Nightmarify(input)

	// The obfuscated output should contain only Base64-like characters
	// (alphanumeric, +, /, =) but decode to garbage, not hex, not the original.
	for _, c := range obfuscated {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			t.Errorf("unexpected character %c in nightmarified output", c)
		}
	}
}
