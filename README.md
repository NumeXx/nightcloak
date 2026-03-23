# NightCloak

A statically-linked Go binary that unifies metadata steganography and string obfuscation into a single tool. NightCloak embeds encrypted payloads into file metadata (EXIF, ID3, Matroska, XMP) through a three-layer pipeline: obfuscation, authenticated encryption, and metadata injection.

This project is a port and modernization of the original [cloak.sh](https://github.com/Jiab77) steganography tool and [nightmare](https://codeberg.org/Jiab77/base82) obfuscation tool created by **Doctor Who (Jiab77)**. The core logic, metadata wire format, and operational philosophy are preserved. The implementation is new.

## Demo

[![asciicast](https://asciinema.org/a/861939.svg)](https://asciinema.org/a/861939)

## How It Works

```
             hide                                    reveal
             ----                                    ------

  payload                                     carrier file
     |                                             |
     v                                             v
  hex encode ──> base64 ──> ROT13/5         exiftool -json ──> parse Description tag
     |          (nightmare layer)                  |
     v                                             v
  PBKDF2(password, salt) ──> ChaCha20-Poly1305    ChaCha20-Poly1305 ──> verify tag ──> decrypt
     |                       (crypto layer)        |
     v                                             v
  exiftool -@ - (stdin stream)              ROT13/5 ──> base64 decode ──> hex decode
     |          (cloak layer)                      |
     v                                             v
  carrier file with embedded payload          original payload
```

Folders are compressed to zip archives in memory before entering the pipeline. The entire chain runs without writing intermediate plaintext to disk.

## Attribution

The original tools were written by **Doctor Who (Jiab77)**:

- **cloak.sh** (v0.2.1) -- Bash steganography tool that hides encrypted data inside file metadata using `exiftool` and `ffmpeg`.
- **nightmare** (v0.0.0) -- Bash string obfuscator using a Hex-to-Base82 chain that produces output resembling Base64 but failing every standard decoder.
- **base82** -- Jiab77's custom encoding scheme (hosted on [Codeberg](https://codeberg.org/Jiab77/base82)), which is Base64 with a ROT13+ROT5 character substitution overlay.

NightCloak is a ground-up Go rewrite. It is not a wrapper around the original scripts.

## Modernizations

### Authenticated Encryption

The original `cloak.sh` uses `openssl chacha20 -pbkdf2`, which is an unauthenticated stream cipher. A tampered ciphertext decrypts silently to garbage with no indication of corruption.

NightCloak uses **ChaCha20-Poly1305** (AEAD). Every decryption operation verifies a 16-byte Poly1305 authentication tag before returning plaintext. If the payload has been modified, the password is wrong, or the ciphertext is truncated, decryption fails explicitly.

### Self-Contained Key Derivation

The original tool generates a `key.dat` file on first run (`openssl rand -base64 32`) and requires it to be present for decryption. Losing this file means losing access to all embedded payloads.

NightCloak derives keys from a user password using **PBKDF2-HMAC-SHA256** (100,000 iterations). A random 12-byte salt is generated per encryption and stored in the ciphertext header. No external key files.

Wire format: `[12B salt][12B nonce][ciphertext + 16B Poly1305 tag]`

### Zero-Dependency Core

All obfuscation and cryptographic operations run natively in Go:

| Original dependency | Replaced by |
|---|---|
| `openssl` CLI | `golang.org/x/crypto/chacha20poly1305`, `pbkdf2` |
| `xxd` | `encoding/hex` |
| `base64` CLI | `encoding/base64` |
| `base82` binary | Custom `rot13_5` + `encoding/base64` |
| `jq` | `encoding/json` |
| `zip` / `7z` | `archive/zip` |

The `openssl` process is no longer visible in `ps aux` output during encryption. The password is never passed as an argument to a child process (the original passes it to `openssl` via `-pass`). If the password is provided via `-p`, it is visible in the `nightcloak` process arguments itself -- omit `-p` to be prompted interactively instead.

### Stream-Centric Architecture

The original `cloak.sh` writes the full encrypted payload to a temporary file, then passes it to exiftool via `-@ <tempfile>`. For large payloads, this creates a forensic artifact on disk.

NightCloak streams data directly into exiftool's stdin using `-@ -` and a goroutine-driven `io.Pipe()`. The payload flows from memory into the tool's stdin without touching the filesystem. This also bypasses the kernel's `ARG_MAX` limit (~256KB on macOS, ~2MB on Linux) that would reject large payloads passed as CLI arguments.

For ffmpeg (used with `.mp3`, `.avi`, `.ogg` containers), a temporary FFMETADATA1 file is still required because ffmpeg needs a seekable file for its second `-i` input. It is removed immediately after use.

## Usage

### Build

```
CGO_ENABLED=0 go build -o nightcloak cmd/nightcloak/main.go
```

Produces a single static binary (~3.4MB, no CGO, no runtime dependencies beyond exiftool/ffmpeg).

### Hide a payload

```bash
# String
nightcloak hide photo.jpg "attack at dawn" -p mypassword

# File
nightcloak hide photo.jpg plans.pdf -p mypassword -k

# Folder (zipped in memory)
nightcloak hide photo.jpg ./confidential/ -p mypassword -o output.jpg

# From stdin
tar cz ./src | nightcloak hide photo.jpg - -p mypassword
```

The `-k` flag keeps the original carrier (writes to `photo.mod.jpg`). Without it, the carrier is replaced in place.

### Reveal a payload

```bash
# String payloads print to stdout
nightcloak reveal photo.jpg -p mypassword

# File payloads write to the original filename
nightcloak reveal photo.jpg -p mypassword
# [*] Extracted to plans.pdf (14832 bytes)

# Override output path
nightcloak reveal photo.jpg -p mypassword -o recovered.bin
```

### Inspect metadata

```bash
# View all tags (no password needed)
nightcloak inspect photo.jpg
```

Shows the raw exiftool JSON output. Useful for verifying that the `Comment` and `Description` tags contain cloak data.

### Dump raw decrypted data

```bash
# Decrypt but skip de-obfuscation (outputs nightmarified string)
nightcloak dump photo.jpg -p mypassword

# Pipe to file(1) to identify the data type
nightcloak dump photo.jpg -p mypassword | file -
```

### Obfuscate strings (no encryption)

```bash
# Encode
nightcloak obfuscate "hello world"
# Output: AQt7AGMwAzZ7MwVjAwL8ZwZ7MwpmAmx=

# Decode
nightcloak deobfuscate "AQt7AGMwAzZ7MwVjAwL8ZwZ7MwpmAmx="
# Output: hello world

# Pipe chain
echo "test" | nightcloak obfuscate - | nightcloak deobfuscate -
```

## Requirements

| Dependency | Required for | Install |
|---|---|---|
| Go 1.25+ | Building from source | [golang.org](https://go.dev/dl/) |
| `exiftool` | Embedding/extracting metadata (JPG, PNG, PDF, etc.) | `brew install exiftool` / `apt install libimage-exiftool-perl` |
| `ffmpeg` / `ffprobe` | Embedding metadata in `.mp3`, `.avi`, `.ogg` containers | `brew install ffmpeg` / `apt install ffmpeg` |

## Tests

```bash
go test ./... -v
```

38 tests across three packages:

- `pkg/nightmare` -- ROT13/5 self-inverse property, known character mappings, encode/decode roundtrips, output format validation.
- `pkg/crypto` -- Encrypt/decrypt roundtrips (unicode, binary, 100KB payloads), wrong password rejection, ciphertext uniqueness, tamper detection, wire format verification.
- `pkg/cloak` -- Description tag parsing (file, string, malformed, PDF workaround), validation, zip compression (with subdirectories), integration tests with real exiftool (auto-skipped if not installed).

## Compatibility

NightCloak is **not** a drop-in replacement for the original Bash tools. Files hidden by `cloak.sh` cannot be revealed by `nightcloak`, and vice versa. The differences:

1. The Bash `<<<` here-string operator appends a newline to input, so `nightmare` hex-encodes `"hello\n"` while NightCloak hex-encodes `"hello"`. The obfuscated outputs differ.
2. The encryption uses a different cipher (AEAD vs raw stream) with a different wire format.

The metadata tag structure (`N:;F:` and `S:` prefixes, `"Modified by Cloak"` sentinel) is identical.

## Project Structure

```
cmd/nightcloak/main.go          CLI entry point (6 commands, zero-dependency flag parser)
pkg/nightmare/base82.go         ROT13+ROT5 substitution cipher, Base82Encode/Decode
pkg/nightmare/nightmare.go      Nightmarify/Dreamify for strings and byte slices
pkg/crypto/crypto.go            ChaCha20-Poly1305 AEAD with PBKDF2 key derivation
pkg/cloak/cloak.go              Hide/Reveal/Inspect/ZipFolder, exiftool and ffmpeg paths
```

## Disclaimer

This tool is intended for authorized security testing, research, and educational purposes. Use it responsibly and in compliance with applicable laws. The authors are not responsible for misuse.

## Credits

- **Doctor Who (Jiab77)** -- Original author of `cloak.sh`, `nightmare`, and `base82`.
