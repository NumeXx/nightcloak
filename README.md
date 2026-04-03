# NightCloak

A statically-linked Go binary that unifies metadata steganography and string obfuscation into a single tool. NightCloak embeds encrypted payloads into file metadata (EXIF, ID3, XMP) through a multi-layer pipeline: obfuscation, authenticated encryption, and native binary injection. It also supports distributed resiliency via Reed-Solomon erasure coding and CRC64 algebraic beacon discovery.

This project is a port and modernization of the original [cloak.sh](https://github.com/Jiab77/cloak) steganography tool and [nightmare](https://codeberg.org/Jiab77/nightmare) obfuscation tool created by **Doctor Who (Jiab77)**. The core logic, metadata wire format, and operational philosophy are preserved. The implementation is new.

## Demo

[![asciicast](https://asciinema.org/a/Cy4iyjsL1FAJd8OE.svg)](https://asciinema.org/a/Cy4iyjsL1FAJd8OE)

## How It Works

### Single-Carrier Pipeline

```
             hide                                    reveal
             ----                                    ------

  payload                                     carrier file
     |                                             |
     v                                             v
  hex encode ──> base64 ──> ROT13/5         parse metadata ──> extract payload
     |          (nightmare layer)                  |
     v                                             v
  Argon2id(password, salt) ──> ChaCha20-Poly1305   ChaCha20-Poly1305 ──> verify tag ──> decrypt
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

### Distributed Pipeline (Ghost Network)

```
              split                                  gather
              -----                                  ------

  payload                                     N carrier files in directory
     |                                             |
     v                                             v
  nightmare + Argon2id + ChaCha20 encrypt  CRC64 beacon scan (parallel, NumCPU workers)
     |                                   Beacon = HMAC-SHA256(password, "nightcloak-beacon-v1")[:8]
     v                                             |
  Reed-Solomon(K data, P parity)                   v
  ──> K+P encoded shard blobs            RevealReader per matched carrier (parallel)
     |   each with 52-byte manifest            |
     |   (index, K, P, PayloadID, size)        v
     v                                   group shards by PayloadID
  inject each shard into a carrier       Reed-Solomon reconstruct (tolerates up to P lost)
     |                                         |
     v                                         v
  append 8 CRC64 alignment bytes        Argon2id + ChaCha20 decrypt ──> nightmare decode
  so file CRC64 == beacon target              |
     |                                         v
     v                                   original payload
  N carrier files, each CRC64-tagged
```

Any K of the K+P carrier files are sufficient to recover the original payload. The beacon allows stateless discovery of carrier files in any directory without a manifest or filename list.

## Attribution

The original tools were written by **Doctor Who (Jiab77)**:

- **cloak.sh** (v0.2.1) -- Bash steganography tool that hides encrypted data inside file metadata using `exiftool` and `ffmpeg`.
- **nightmare** (v0.0.0) -- Bash string obfuscator using a Hex-to-Base82 chain that produces output resembling Base64 but failing every standard decoder.
- **base82** -- Jiab77's custom encoding scheme (hosted on [Codeberg](https://codeberg.org/Jiab77/base82)), which is Base64 with a ROT13+ROT5 character substitution overlay.

NightCloak is a ground-up Go rewrite by **Me (NumeX)**. It is not a wrapper around the original scripts.

## Modernizations

### Authenticated Encryption

The original `cloak.sh` uses `openssl chacha20 -pbkdf2`, which is an unauthenticated stream cipher. A tampered ciphertext decrypts silently to garbage with no indication of corruption.

NightCloak uses **ChaCha20-Poly1305** (AEAD). Every decryption operation verifies a 16-byte Poly1305 authentication tag before returning plaintext. If the payload has been modified, the password is wrong, or the ciphertext is truncated, decryption fails explicitly.

### Multi-Layer Security (XChaCha20)

NightCloak supports an optional secondary encryption layer using **XChaCha20-Poly1305**. When the `KEY` environment variable is set, the payload is wrapped in an additional encrypted envelope with an independent 24-byte nonce. This provides double-layered protection with independent key material.

### Memory-Hard Key Derivation (Argon2id)

NightCloak derives encryption keys using **Argon2id** (time=3, memory=64MB, parallelism=4). Unlike PBKDF2, Argon2id is memory-hard: each password attempt requires 64MB of RAM, making GPU-based brute-force attacks economically infeasible regardless of hardware budget. A random 16-byte salt is generated per encryption and stored in the ciphertext header. No external key files required.

Old blobs encrypted with the legacy PBKDF2 layer are transparently detected and still decrypt correctly.

### Native Zero-Dependency Engine

All obfuscation and cryptographic operations run natively in Go. For the most common formats, NightCloak performs surgical binary manipulation without spawning child processes or touching temporary files:

- **PNG:** Injects a tEXt chunk before the IEND marker. The injector streams the file chunk-by-chunk without loading the full carrier into memory.
- **JPEG (Stealth/Default):** Constructs a parallel APP1 segment containing a valid TIFF/EXIF structure. The payload is stored in the UserComment (0x9286) tag with an undefined charset prefix, making the binary payload indistinguishable from camera-vendor encoded comments.
- **MP3:** Injects a TXXX frame into the ID3v2 tag. Uses a **padding-first optimization** that overwrites existing ID3v2 padding to avoid shifting the audio stream, ensuring bit-perfect audio preservation. Verified by SHA256 comparison in the test suite.
- **PDF:** Implements a **Native Purge Engine** that parses the full XREF chain and re-emits a clean single-pass PDF. This eliminates incremental update artifacts and ghost data traces common in PDF metadata editors. Falls back to exiftool for PDF 1.5+ compressed XREF streams and encrypted PDFs.

### Surgical Wipe

The `wipe` command removes an embedded payload from a carrier file and restores it to a clean state. The operation is format-aware: PNG drops the matching tEXt chunk, JPEG strips the injected APP1 segment, MP3 removes the TXXX frame, PDF purge-rewrites without /Keywords. Carrier timestamps are restored after wipe.

### Distributed Resiliency (Reed-Solomon + CRC64 Beacon)

NightCloak implements a distributed steganography layer that splits a payload across multiple carrier files with erasure-code redundancy:

- **Reed-Solomon encoding** (`pkg/shard`): A `(K, P)` scheme splits the encrypted payload into K data shards plus P parity shards. Any K of the K+P carriers are sufficient for full recovery — up to P carriers may be lost or deleted.

- **CRC64 algebraic beacon**: Each carrier file has 8 bytes appended such that `CRC64(file) == HMAC-SHA256(password, "nightcloak-beacon-v1")[:8]`. The 8-byte solution is computed in O(64) using the precomputed inverse of the CRC64/ECMA GF(2)-linear map. A parallel scanner (`NumCPU` goroutines) identifies all carrier files in a directory tree in a single pass — no filename list, no manifest file, no external state.

- **Self-describing shard manifests**: Each shard carries a 52-byte header containing its index, total shard counts, original payload size, and a per-payload HMAC identifier. The scanner can group shards from multiple independent split operations in a single directory.

### Automation and Environment Variables

NightCloak integrates into automated pipelines via environment variables:

| Variable | Priority | Behavior |
|---|---|---|
| `NIGHT_PASSWORD` | 2nd (after `-p` flag) | Primary decryption password |
| `KEY` | Checked per operation | Secondary XChaCha20 key (any string, or a Base58-decoded 32-byte key) |
| `KEY=-` | Checked per operation | Generate a random key, print Base58 to stderr, use for this operation |

### Cross-Platform Builds

NightCloak cross-compiles cleanly to all major platforms without CGO:

```bash
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

## Usage

### Build

```bash
CGO_ENABLED=0 go build -o nightcloak cmd/nightcloak/main.go
```

Produces a single static binary with no runtime dependencies for core formats.

### Single-Carrier Operations

```bash
# Hide a payload in a JPEG
nightcloak hide photo.jpg "secret message" -p mypass

# Automated carrier discovery (scans current directory tree)
nightcloak hide payload.bin -p mypass

# Double encryption: primary password + secondary XChaCha20 key
KEY=- nightcloak hide photo.jpg payload.bin -p mypass
# stderr: [KEY] <base58key>  <- save this for reveal

# Reveal
nightcloak reveal photo.jpg -p mypass
KEY="<base58key>" nightcloak reveal photo.jpg -p mypass

# Wipe: remove embedded payload, restore carrier to clean state
nightcloak wipe photo.jpg -p mypass

# Pipe to stdout
nightcloak reveal photo.jpg -p mypass | file -
```

### Distributed Ghost Network

```bash
# Split a payload across 6 carriers (recover from any 4)
nightcloak split secret.bin ./media/ -n 6 -k 4 -p mypass

# Scan a directory for beacon-matching carriers
nightcloak scan ./media/ -p mypass

# Reconstruct from surviving carriers (tolerates up to 2 lost)
nightcloak gather ./media/ -p mypass -o recovered.bin

# Full pipeline with double encryption
export NIGHT_PASSWORD="mypass"
export KEY="myxkey"
nightcloak split secret.bin ./media/ -n 6 -k 4
nightcloak gather ./media/ -o recovered.bin
```

### Automation

```bash
export NIGHT_PASSWORD="mypassword"

# No -p flag needed
nightcloak hide photo.jpg secret.bin -o hidden.jpg
nightcloak reveal hidden.jpg

# Generate a random XChaCha20 key
KEY=- nightcloak hide photo.jpg payload.bin
```

## Requirements

| Dependency | Required for | Install |
|---|---|---|
| Go 1.21+ | Building from source | [golang.org](https://go.dev/dl/) |
| `exiftool` | TIFF, encrypted PDF, PDF 1.5+ compressed XREF (optional) | `brew install exiftool` / `apt install libimage-exiftool-perl` |
| `ffmpeg` | AVI, OGG containers (optional) | `brew install ffmpeg` / `apt install ffmpeg` |

Core formats (**PNG, JPEG, MP3, PDF**) require no external tools. The distributed pipeline (`split`/`gather`/`scan`) requires no external tools on any platform.

## Tests

```bash
go test ./... -v
```

115 tests across five packages (`nightmare`, `crypto`, `cloak`, `cloak/native`, `shard`) covering byte-level integrity, cryptographic roundtrips, Reed-Solomon recovery, CRC64 algebraic inversion, and forensic cleanliness.

## Native Zero-Dependency Status

| Format | Injection method | External tool needed? |
|---|---|---|
| `.jpg` / `.jpeg` | Native EXIF APP1 UserComment | No |
| `.png` | Native tEXt chunk | No |
| `.mp3` | Native ID3v2 TXXX frame | No |
| `.pdf` (flat XREF) | Native /Info /Keywords + purge rewrite | No |
| `.pdf` (1.5+ XREF stream / encrypted) | exiftool fallback | Yes |
| `.avi` / `.ogg` | ffmpeg FFMETADATA1 | Yes |
| `.tiff` / others | exiftool | Yes |

## Disclaimer

This tool is intended for authorized security testing, research, and educational purposes. Use it responsibly and in compliance with applicable laws.

## Credits

- **Me (NumeX)** -- Go modernization, native engines, distributed resiliency layer
- **Doctor Who (Jiab77)** -- Original author of `cloak.sh`, `nightmare`, and `base82`
