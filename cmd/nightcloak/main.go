package main

import (
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nightcloak/pkg/cloak"
	"nightcloak/pkg/cloak/native"
	"nightcloak/pkg/crypto"
	"nightcloak/pkg/nightmare"
	)

	const version = "0.9.0-rc1"

	const banner = `
	╔╗╔╦═╗╔═╗╦ ╦╔╦╗╔═╗╦  ╔═╗╔═╗╦╔═
	║║║║ ╠╣ ╦╠═╣ ║ ║  ║  ║ ║╠═╣╠╩╗
	╝╚╝╩═╝╚═╝╩ ╩ ╩ ╚═╝╩═╝╚═╝╩ ╩╩ ╩
	─── nightmare + cloak ── v%s ───
	`

	func main() {
	if len(os.Args) < 2 {
	        printUsage()
	        os.Exit(1)
	}

	switch os.Args[1] {
	case "hide":
	        cmdHide(os.Args[2:])
	case "reveal":
	        cmdReveal(os.Args[2:])
	case "exec":
	        cmdExec(os.Args[2:])
	case "inspect":
	        cmdInspect(os.Args[2:])
	case "dump":
	        cmdDump(os.Args[2:])
	case "obfuscate":
	        cmdObfuscate(os.Args[2:])
	case "deobfuscate":
	        cmdDeobfuscate(os.Args[2:])
	case "-h", "--help", "help":
	        printHelp()
	case "-v", "--version", "version":
	        fmt.Printf("nightcloak %s\n", version)
	case "--thc":
	        printTHC()
	default:
	        die("unknown command: %s", os.Args[1])
	}
	}

	// ---------------------------------------------------------------------------
	// hide: nightmarify → encrypt → embed
	// ---------------------------------------------------------------------------
func cmdHide(args []string) {
	var password, output string
	var keepOriginal bool
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-o": &output, "--output": &output,
	}, map[string]*bool{
		"-k": &keepOriginal, "--keep": &keepOriginal,
	})

	// Auto-finder: if only one positional arg, treat it as payload and
	// discover the carrier from supported media files in the current tree.
	var carrierPath, payloadArg string
	switch len(args) {
	case 0:
		die("usage: nightcloak hide [<carrier>] <payload|file|-> [-p password] [-o output] [-k]")
	case 1:
		payloadArg = args[0]
		found, err := findCarrier()
		if err != nil {
			die("carrier auto-finder: %v", err)
		}
		carrierPath = found
		log("Auto-selected carrier: %s", carrierPath)
	default:
		carrierPath = args[0]
		payloadArg = args[1]
	}

	password = resolvePassword(password)

	// Determine payload source: file, stdin, or inline string.
	payload, payloadName, payloadType := resolvePayload(payloadArg)

	// Step 1: Nightmarify (obfuscate).
	obfuscated := nightmare.NightmarifyBytes(payload)

	// Step 2: Primary encrypt (ChaCha20-Poly1305 + PBKDF2).
	encrypted, err := crypto.Encrypt([]byte(obfuscated), password)
	if err != nil {
		die("encryption failed: %v", err)
	}

	// Step 3: Optional secondary XChaCha20-Poly1305 layer (KEY env var).
	xkey, err := crypto.ResolveXKey()
	if err != nil {
		die("KEY resolution failed: %v", err)
	}
	if xkey != nil {
		encrypted, err = crypto.XEncrypt(encrypted, xkey)
		if err != nil {
			die("secondary encryption failed: %v", err)
		}
	}

	// Step 3: Embed via cloak.
	opts := cloak.HideOpts{
		CarrierPath: carrierPath,
		OutputPath:  output,
		Payload:     encrypted,
		PayloadName: payloadName,
		Type:        payloadType,
		Password:    password,
	}
	if keepOriginal && output == "" {
		// Generate a default output path to avoid overwriting.
		ext := filepath.Ext(carrierPath)
		stem := strings.TrimSuffix(carrierPath, ext)
		opts.OutputPath = stem + ".mod" + ext
	}

	if err := cloak.Hide(opts); err != nil {
		die("embedding failed: %v", err)
	}

	target := opts.OutputPath
	if target == "" {
		target = carrierPath
	}
	log("Payload hidden in %s", target)
}

// ---------------------------------------------------------------------------
// reveal: extract → decrypt → dreamify
// ---------------------------------------------------------------------------

func cmdReveal(args []string) {
	var password, output string
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-o": &output, "--output": &output,
	}, map[string]*bool{})

	if len(args) < 1 {
		die("usage: nightcloak reveal <carrier> [-p password] [-o output]")
	}

	carrierPath := args[0]

	password = resolvePassword(password)

	// Step 1: Extract via cloak.
	result, err := cloak.Reveal(carrierPath, password)
	if err != nil {
		die("extraction failed: %v", err)
	}

	raw := result.Payload

	// Step 2: Strip optional secondary XChaCha20 layer (KEY env var).
	xkey, err := crypto.ResolveXKey()
	if err != nil {
		die("KEY resolution failed: %v", err)
	}
	if xkey != nil {
		raw, err = crypto.XDecrypt(raw, xkey)
		if err != nil {
			die("secondary decryption failed: %v", err)
		}
	}

	// Step 3: Primary decrypt (ChaCha20-Poly1305 + PBKDF2).
	decrypted, err := crypto.Decrypt(raw, password)
	if err != nil {
		die("decryption failed: %v", err)
	}

	// Step 4: Dreamify (de-obfuscate).
	clearBytes, err := nightmare.DreamifyBytes(string(decrypted))
	if err != nil {
		die("de-obfuscation failed: %v", err)
	}

	// Output.
	if result.Type == cloak.PayloadFile && output == "" {
		output = result.PayloadName
	}

	if output != "" {
		if err := os.WriteFile(output, clearBytes, 0o644); err != nil {
			die("writing output file: %v", err)
		}
		log("Extracted to %s (%d bytes)", output, len(clearBytes))
	} else {
	        os.Stdout.Write(clearBytes)
	}
	}

	// ---------------------------------------------------------------------------
	// exec: extract → decrypt → dreamify → in-memory execution
	// ---------------------------------------------------------------------------

	func cmdExec(args []string) {
	var password string
	args = parseFlags(args, map[string]*string{
	        "-p": &password, "--password": &password,
	}, map[string]*bool{})

	if len(args) < 1 {
	        die("usage: nightcloak exec <carrier> [-- <args...>]")
	}

	carrierPath := args[0]
	execArgs := args[1:]

	password = resolvePassword(password)
	// Step 1: Extract via cloak.
	result, err := cloak.Reveal(carrierPath, password)
	if err != nil {
	        die("extraction failed: %v", err)
	}

	raw := result.Payload

	// Step 2: Strip optional secondary XChaCha20 layer (KEY env var).
	xkey, err := crypto.ResolveXKey()
	if err != nil {
	        die("KEY resolution failed: %v", err)
	}
	if xkey != nil {
	        raw, err = crypto.XDecrypt(raw, xkey)
	        if err != nil {
	                die("secondary decryption failed: %v", err)
	        }
	}

	// Step 3: Primary decrypt (ChaCha20-Poly1305 + PBKDF2).
	decrypted, err := crypto.Decrypt(raw, password)
	if err != nil {
	        die("decryption failed: %v", err)
	}

	// Step 4: Dreamify (de-obfuscate).
	clearBytes, err := nightmare.DreamifyBytes(string(decrypted))
	if err != nil {
	        die("de-obfuscation failed: %v", err)
	}

	// Step 5: Execute directly from memory.
	log("Executing payload in-memory...")
	if err := native.MemExec(clearBytes, execArgs); err != nil {
	        die("in-memory execution failed: %v", err)
	}
	}

	// ---------------------------------------------------------------------------
	// inspect: show file metadata tags
	// ---------------------------------------------------------------------------
func cmdInspect(args []string) {
	if len(args) < 1 {
		die("usage: nightcloak inspect <file>")
	}

	data, err := cloak.Inspect(args[0])
	if err != nil {
		die("inspect failed: %v", err)
	}
	os.Stdout.Write(data)
	fmt.Println()
}

// ---------------------------------------------------------------------------
// dump: extract → decrypt → raw stdout (no de-obfuscation, no file write)
// ---------------------------------------------------------------------------

func cmdDump(args []string) {
	var password string
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
	}, map[string]*bool{})

	if len(args) < 1 {
		die("usage: nightcloak dump <carrier> [-p password]")
	}

	carrierPath := args[0]

	password = resolvePassword(password)

	// Step 1: Extract.
	result, err := cloak.Reveal(carrierPath, password)
	if err != nil {
		die("extraction failed: %v", err)
	}

	raw := result.Payload

	// Step 2: Strip optional secondary XChaCha20 layer.
	xkey, err := crypto.ResolveXKey()
	if err != nil {
		die("KEY resolution failed: %v", err)
	}
	if xkey != nil {
		raw, err = crypto.XDecrypt(raw, xkey)
		if err != nil {
			die("secondary decryption failed: %v", err)
		}
	}

	// Step 3: Primary decrypt.
	decrypted, err := crypto.Decrypt(raw, password)
	if err != nil {
		die("decryption failed: %v", err)
	}

	// Dump raw decrypted bytes to stdout (still nightmarified).
	os.Stdout.Write(decrypted)
}

// ---------------------------------------------------------------------------
// obfuscate / deobfuscate: pure nightmare layer
// ---------------------------------------------------------------------------

func cmdObfuscate(args []string) {
	if len(args) < 1 {
		die("usage: nightcloak obfuscate <string|->")
	}

	input := readInlineOrStdin(args[0])
	fmt.Print(nightmare.Nightmarify(input))
}

func cmdDeobfuscate(args []string) {
	if len(args) < 1 {
		die("usage: nightcloak deobfuscate <string|->")
	}

	input := readInlineOrStdin(args[0])
	result, err := nightmare.Dreamify(input)
	if err != nil {
		die("de-obfuscation failed: %v", err)
	}
	fmt.Print(result)
}

// ---------------------------------------------------------------------------
// payload resolution
// ---------------------------------------------------------------------------

func resolvePayload(arg string) (data []byte, name string, pt cloak.PayloadType) {
	// Stdin.
	if arg == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("reading stdin: %v", err)
		}
		return data, "stdin", cloak.PayloadFile
	}

	info, statErr := os.Stat(arg)

	// Directory → zip in-memory, then embed as file payload.
	if statErr == nil && info.IsDir() {
		log("Compressing folder %s...", arg)
		zipData, zipName, err := cloak.ZipFolder(arg)
		if err != nil {
			die("compressing folder: %v", err)
		}
		log("Compressed to %s (%d bytes)", zipName, len(zipData))
		return zipData, zipName, cloak.PayloadFile
	}

	// File.
	if statErr == nil && !info.IsDir() {
		data, err := os.ReadFile(arg)
		if err != nil {
			die("reading file %s: %v", arg, err)
		}
		return data, filepath.Base(arg), cloak.PayloadFile
	}

	// Inline string.
	return []byte(arg), "", cloak.PayloadString
}

func readInlineOrStdin(arg string) string {
	if arg == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("reading stdin: %v", err)
		}
		return strings.TrimRight(string(data), "\n")
	}
	return arg
}

// ---------------------------------------------------------------------------
// flag parsing (zero-dependency, handles intermixed flags and positionals)
// ---------------------------------------------------------------------------

func parseFlags(args []string, strFlags map[string]*string, boolFlags map[string]*bool) []string {
	var positional []string
	for i := 0; i < len(args); i++ {
		if dest, ok := strFlags[args[i]]; ok {
			if i+1 >= len(args) {
				die("flag %s requires a value", args[i])
			}
			i++
			*dest = args[i]
		} else if dest, ok := boolFlags[args[i]]; ok {
			*dest = true
		} else if args[i] == "--" {
			positional = append(positional, args[i+1:]...)
			break
		} else {
			positional = append(positional, args[i])
		}
	}
	return positional
}

// ---------------------------------------------------------------------------
// carrier auto-finder
// ---------------------------------------------------------------------------

// carrierExtensions are the file types eligible for automatic carrier selection.
var carrierExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".pdf": true,
}

type carrierCandidate struct {
	path  string
	mtime time.Time
}

// findCarrier walks the current directory tree and returns a carrier file
// from the 2nd or 3rd quartile of the mtime distribution (files that are
// old enough to be unremarkable but not so old as to stand out as artifacts).
// Falls back to a random pick if fewer than 4 candidates exist.
func findCarrier() (string, error) {
	var candidates []carrierCandidate

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() || !carrierExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		candidates = append(candidates, carrierCandidate{path: path, mtime: info.ModTime()})
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no suitable carrier found (.png/.jpg/.jpeg/.pdf) in current directory tree")
	}

	// Sort oldest → newest.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].mtime.Before(candidates[j].mtime)
	})

	// Select from Q2/Q3 when there are enough candidates; otherwise pick randomly.
	var pool []carrierCandidate
	n := len(candidates)
	if n >= 4 {
		q1 := n / 4
		q3 := (3 * n) / 4
		pool = candidates[q1:q3]
	} else {
		pool = candidates
	}

	chosen := pool[rand.Intn(len(pool))]
	abs, _ := filepath.Abs(chosen.path)
	fmt.Fprintf(os.Stderr, "  [carrier] %s\n", abs)
	return chosen.path, nil
}

// ---------------------------------------------------------------------------
// password resolution
// ---------------------------------------------------------------------------

// resolvePassword returns the password from, in priority order:
//  1. The explicit flag value (-p / --password)
//  2. The NIGHT_PASSWORD environment variable
//  3. An interactive terminal prompt
func resolvePassword(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("NIGHT_PASSWORD"); env != "" {
		return env
	}
	fmt.Fprint(os.Stderr, "Enter password: ")
	var pw string
	fmt.Scanln(&pw)
	if pw == "" {
		die("password cannot be empty")
	}
	return pw
}

func printTHC() {
	fmt.Fprintln(os.Stderr, `
  The Hacker's Choice -- https://www.thc.org

  This tool carries the spirit of THC's work: small, sharp, and silent.
  The steganography philosophy and the "nightmare" obfuscation chain
  were directly inspired by the techniques pioneered by Doctor Who (Jiab77) & Skyper.`)
}

// ---------------------------------------------------------------------------
// output helpers
// ---------------------------------------------------------------------------

func printUsage() {
	fmt.Fprintf(os.Stderr, banner, version)
	fmt.Fprintln(os.Stderr, `
  Usage: nightcloak <command> [options]

  Commands:
    hide          Obfuscate, encrypt, and embed payload in a carrier file
    reveal        Extract, decrypt, and de-obfuscate payload from carrier
    exec          Direct in-memory execution of payload (Linux only)
    inspect       Show file metadata tags (no decryption)
    dump          Extract and decrypt to stdout (raw, no de-obfuscation)
    obfuscate     Pure nightmare encoding (no encryption)
    deobfuscate   Reverse nightmare encoding

  Run 'nightcloak <command> --help' or 'nightcloak help' for details.`)
}

func printHelp() {
	fmt.Fprintf(os.Stderr, banner, version)
	fmt.Fprintln(os.Stderr, `
  Usage: nightcloak <command> [options]

  Commands:

    hide <carrier> <payload|file|folder|-> [flags]
        Obfuscate → Encrypt → Embed payload into carrier file metadata.
        Folders are automatically zipped before embedding.

        -p, --password <pw>   Encryption password (prompted if omitted)
        -o, --output <path>   Write to path instead of replacing carrier
        -k, --keep            Keep original carrier (auto-generates output path)

        Examples:
          nightcloak hide photo.jpg "secret message" -p mypass
          nightcloak hide photo.jpg secret.txt -p mypass
          nightcloak hide photo.jpg ./secret_folder/ -p mypass -k
          cat payload.bin | nightcloak hide photo.jpg - -p mypass

    reveal <carrier> [flags]
        Extract → Decrypt → De-obfuscate payload from carrier file.

        -p, --password <pw>   Decryption password (prompted if omitted)
        -o, --output <path>   Write to path instead of stdout/original name

        Examples:
          nightcloak reveal photo.jpg -p mypass
          nightcloak reveal photo.jpg -p mypass -o recovered.txt

    exec <carrier> [-- <args...>] [flags]
        Extract → Decrypt → De-obfuscate → Direct in-memory execution.
        The binary never touches the disk (Linux only).

        -p, --password <pw>   Decryption password (prompted if omitted)

        Examples:
          nightcloak exec carrier.pdf -p mypass
          nightcloak exec carrier.pdf -p mypass -- -a -l

    inspect <file>
        Show all metadata tags from a file (no decryption).

        Examples:
          nightcloak inspect photo.jpg

    dump <carrier> [-p password]
        Extract and decrypt to stdout without de-obfuscation.
        Useful for debugging or piping raw decrypted data.

        Examples:
          nightcloak dump photo.jpg -p mypass
          nightcloak dump photo.jpg -p mypass | file -

    obfuscate <string|->
        Pure nightmare encoding (hex → base82). No encryption.

        Examples:
          nightcloak obfuscate "hello world"
          echo "hello" | nightcloak obfuscate -

    deobfuscate <string|->
        Reverse nightmare encoding.

        Examples:
          nightcloak deobfuscate "Awt7AGMwAzZ7Mt=="
          echo "Awt7AGMwAzZ7Mt==" | nightcloak deobfuscate -

  Requires: exiftool (most formats), ffmpeg/ffprobe (mp3/avi/ogg)`)
}

func log(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  [*] "+format+"\n", args...)
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  [!] Error: "+format+"\n", args...)
	os.Exit(1)
}
