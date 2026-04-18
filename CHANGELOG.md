# Changelog

## v1.0.0 — 2026-04-18

- `poly-hide`: append encrypted payload as a ZIP archive to JPEG/PNG/PDF carriers
- Result is simultaneously a valid image/PDF and a valid ZIP — viewers parse normally, `unzip`/`7z` extracts ciphertext
- `poly-reveal`: extract and decrypt payload from a polyglot file
- `poly-wipe`: strip the ZIP from a polyglot, restoring the original carrier (no password required)
- ZIP offset patching via EOCD + central directory rebase, making `archive/zip` read correctly after carrier prefix
- Full encryption pipeline: nightmarify + Argon2id/ChaCha20-Poly1305 + optional XChaCha20 secondary layer
- Carrier coverage now complete: metadata injection (PNG/JPEG/MP3/PDF), Unicode zero-width (.txt/.md/.html/.json/.xml/.csv), polyglot ZIP (JPEG/PNG/PDF)

---

## v0.9.9 — 2026-04-16

- Unicode zero-width carrier: `.txt`, `.md`, `.html`, `.htm`, `.json`, `.xml`, `.csv`
- Payload injected as invisible ZWSP/ZWJ bit-encoded chars with ZWNJ frame markers, appended after visible text
- No new commands needed, routing by file extension integrates with existing `hide` / `reveal` / `wipe`
- `wipe` for text carriers is password-free (structural removal, not cryptographic)
- Zero new dependencies

---

## v0.9.8 — 2026-04-05

- `git-hide`: store encrypted payload as a git blob object under a custom ref on any GitHub repo
- `git-reveal`: fetch and decrypt payload from a git repo dead drop
- `git-reveal --exec`: fetch, decrypt, and execute directly from RAM, zero disk touch end-to-end
- `git-wipe`: delete the ref from the remote repo
- Default ref: `refs/nc/latest`, override with `-r` for any ref name (e.g. `refs/notes/ci`)
- Commit messages randomized from a pool of conventional commit patterns to avoid static fingerprint
- Token via `-t` flag or `NIGHTCLOAK_GIT_TOKEN` env var
- Pure stdlib `net/http`, no new dependencies

---

## v0.9.7 — 2026-04-05

- Multi-arch `memfd_create`: amd64 (319), arm64 (279), arm32 (385), mips (4354)
- `execveat(AT_EMPTY_PATH)` replaces `/proc/self/fd/<n>`, no path string in memory
- Inspired by hackerschoice/memexec (Skyper / THC)

---

## v0.9.6 — 2026-04-04

- v3 wire format: `[4B magic][1B flags][16B salt][12B nonce][ciphertext + tag]`
- Random padding (0-512 bytes) always on in v3, same payload produces different ciphertext sizes each run
- `--compress`: DEFLATE before encryption, only activates when it reduces size
- `--lock`: key derived from machine identity (`/etc/machine-id`, `hw.uuid`, MAC fallback)
- `pkg/crypto/machine.go`: handles Linux, macOS, and MAC-address fallback
- `reveal` auto-detects v3 / v2 / v1, no flags needed on the receiving end

---

## v0.9.5 — 2026-04-03

- Native injectors for PNG (tEXt chunk), JPEG (EXIF APP1 UserComment), MP3 (ID3v2 TXXX), PDF (flat XREF purge)
- Argon2id (time=3, mem=64MB, threads=4) replaces PBKDF2
- v2 wire format with 4B magic prefix
- v1 PBKDF2 blobs still decrypt transparently
- `wipe` command: format-aware payload removal, timestamps restored after operation
- Reed-Solomon distributed pipeline: `split` / `gather` / `scan`
- CRC64 algebraic beacon: 8-byte forced match computed in O(64) via GF(2) matrix inversion
- `RevealReader`: accepts pre-loaded bytes, eliminates second disk read during `gather`
- Producer-consumer goroutine pool in `gather` (buffer = workers * 2)
- Parent directory timestamp restoration after carrier modification
- Windows cross-compilation: `timestamp_windows.go` stub (no CGO atime)
- Hidden `--thc` flag

---

## v0.9.4 — 2026-03-28

- Initial release
- Port of cloak.sh + nightmare by Doctor Who (Jiab77)
- ChaCha20-Poly1305 + PBKDF2 key derivation
- Base82 obfuscation chain (hex -> base82 -> ROT13/5)
- `hide` / `reveal` / `wipe` for PNG, JPEG, MP3, PDF, and exiftool fallback
- `exec`: in-memory execution on Linux via `memfd_create`
