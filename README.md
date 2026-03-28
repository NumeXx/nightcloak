# NightCloak

A statically-linked Go binary that unifies metadata steganography and string obfuscation into a single tool. NightCloak embeds encrypted payloads into file metadata (EXIF, ID3, Matroska, XMP) through a multi-layer pipeline: obfuscation, authenticated encryption, and native binary injection.

This project is a port and modernization of the original [cloak.sh](https://github.com/Jiab77/cloak) steganography tool and [nightmare](https://codeberg.org/Jiab77/nightmare) obfuscation tool created by **Doctor Who (Jiab77)**. The core logic, metadata wire format, and operational philosophy are preserved. The implementation is new.

## Demo

[![asciicast](https://asciinema.org/a/Cy4iyjsL1FAJd8OE.svg)](https://asciinema.org/a/Cy4iyjsL1FAJd8OE)

## How It Works

```
             hide                                    reveal
             ----                                    ------

  payload                                     carrier file
     |                                             |
     v                                             v
  hex encode ──> base64 ──> ROT13/5         parse metadata ──> extract payload
     |          (nightmare layer)                  |
     v                                             v
  PBKDF2(password, salt) ──> ChaCha20-Poly1305    ChaCha20-Poly1305 ──> verify tag ──> decrypt
     |                       (crypto layer)        |
     v                                             v
  [Optional] XChaCha20 Layer (KEY env)      [Optional] Strip XChaCha20 (KEY env)
     |                                             |
     v                                             v
  inject into carrier metadata              ROT13/5 ──> base64 decode ──> hex decode
     |          (cloak layer)                      |
     v                                             v
  carrier file with embedded payload          original payload

  Cloak layer routing:
    .png ──> native Go tEXt chunk injection (zero dependencies)
    .jpg/.jpeg ──> native Go EXIF APP1 UserComment injection (zero dependencies)
    .mp3 ──> native Go ID3v2 TXXX injection (zero dependencies)
    .pdf ──> native Go flat-XREF purge & inject (zero dependencies)
    .avi/.ogg ──> ffmpeg FFMETADATA1
    everything else ──> exiftool -@ - (stdin stream)
```

Folders are compressed to zip archives in memory before entering the pipeline. The entire chain runs without writing intermediate plaintext to disk.

## Attribution

The original tools were written by **Doctor Who (Jiab77)**:

- **cloak.sh** (v0.2.1) -- Bash steganography tool that hides encrypted data inside file metadata using `exiftool` and `ffmpeg`.
- **nightmare** (v0.0.0) -- Bash string obfuscator using a Hex-to-Base82 chain that produces output resembling Base64 but failing every standard decoder.
- **base82** -- Jiab77's custom encoding scheme (hosted on [Codeberg](https://codeberg.org/Jiab77/base82)), which is Base64 with a ROT13+ROT5 character substitution overlay.

NightCloak is a ground-up Go rewrite By **Me (NumeX)**. It is not a wrapper around the original scripts.

## Modernizations

### Authenticated Encryption

The original `cloak.sh` uses `openssl chacha20 -pbkdf2`, which is an unauthenticated stream cipher. A tampered ciphertext decrypts silently to garbage with no indication of corruption.

NightCloak uses **ChaCha20-Poly1305** (AEAD). Every decryption operation verifies a 16-byte Poly1305 authentication tag before returning plaintext. If the payload has been modified, the password is wrong, or the ciphertext is truncated, decryption fails explicitly.

### Multi-Layer Security (XChaCha20)

NightCloak supports an optional secondary encryption layer using **XChaCha20-Poly1305**. When the `KEY` environment variable is set, the payload is wrapped in an additional encrypted envelope with an independent 24-byte nonce. This provides double-layered protection for sensitive data.

### Self-Contained Key Derivation

The original tool generates a `key.dat` file on first run (`openssl rand -base64 32`) and requires it to be present for decryption. NightCloak derives keys from a user password using **PBKDF2-HMAC-SHA256**. A random 12-byte salt is generated per encryption and stored in the ciphertext header. No external key files required.

### Native Zero-Dependency Engine

All obfuscation and cryptographic operations run natively in Go. For the most common formats, NightCloak performs surgical binary manipulation without spawning child processes or touching temporary files:

- **PNG:** Injects a tEXt chunk before the IEND marker. The injector streams the file chunk-by-chunk without loading the full carrier into memory.
- **JPEG (Stealth/Default):** Constructs a parallel APP1 segment containing a valid TIFF/EXIF structure. The payload is stored in the UserComment (0x9286) tag with an undefined charset prefix, making the binary payload indistinguishable from camera-vendor encoded comments.
- **MP3:** Injects a TXXX frame into the ID3v2 tag. Uses a **padding-first optimization** that overwrites existing ID3v2 padding to avoid shifting the audio stream, ensuring bit-perfect audio preservation.
- **PDF:** Implements a **Native Purge Engine** that parses the full XREF chain and re-emits a clean single-pass PDF. This eliminates incremental update artifacts and "ghost data" traces common in PDF metadata editors.

### Native Memory Orchestration (Linux)

For advanced research workflows, NightCloak includes an `exec` command that performs **In-Memory Execution**. Using the `memfd_create` syscall, payloads are extracted directly into an anonymous file descriptor in RAM and executed without the binary ever touching the physical disk.

## Usage

### Build

```bash
CGO_ENABLED=0 go build -o nightcloak cmd/nightcloak/main.go
```

Produces a single static binary (~4.3MB, no CGO, zero runtime dependencies for core formats).

### Hide a payload

```bash
# Standard hide
nightcloak hide photo.jpg "secret message" -p mypass

# Automated carrier discovery (scans current tree for .jpg/.png/.pdf)
nightcloak hide payload.bin -p mypass

# Double encryption with random Base58 key generation
KEY=- nightcloak hide photo.jpg payload.bin
# Output: [KEY] 56WDRVGkfjRKAFt54jQRwodFghL5...
```

### Reveal / Execute

```bash
# Extract to file
nightcloak reveal photo.jpg -p mypass

# Direct In-Memory Execution (Linux only)
nightcloak exec carrier.pdf -p mypass -- -arg1 -arg2
```

### Automation and Environment Variables

NightCloak integrates seamlessly into automated pipelines:

- **`NIGHT_PASSWORD`**: Set the primary decryption password.
- **`KEY`**: Set the secondary XChaCha20 key.
- **`KEY=-`**: Automatically generate a secure Base58 key.

## Requirements

| Dependency | Required for | macOS | Linux | Windows |
|---|---|---|---|---|
| Go 1.25+ | Building from source | [golang.org](https://go.dev/dl/) | [golang.org](https://go.dev/dl/) | [golang.org](https://go.dev/dl/) |
| `exiftool` | Legacy formats (TIFF, etc.) | Optional | Optional | Optional |
| `ffmpeg` | Legacy video (AVI, OGG) | Optional | Optional | Optional |

Core formats (**PNG, JPEG, MP3, PDF**) have **Zero Dependencies**.

## Tests

```bash
go test ./... -v
```

Comprehensive test suite covering byte-level integrity, cryptographic roundtrips, and forensic cleanliness.

## Disclaimer

This tool is intended for authorized security testing, research, and educational purposes. Use it responsibly and in compliance with applicable laws.

## Credits

- **Me (NumeX)** -- Go modernization and native engines
- **Doctor Who (Jiab77)** -- Original author of `cloak.sh`, `nightmare`, and `base82`
