// Package gitdrop implements git repository dead-drop steganography.
// Encrypted payloads are stored as git blob objects under a custom ref
// (default: refs/nc/latest). The ref is invisible in GitHub's web UI,
// not fetched on git clone, and the blob content is opaque ciphertext.
package gitdrop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
)

var commitMessages = []string{
	"docs: update README",
	"chore: cleanup",
	"fix: typo",
	"ci: update workflow",
	"chore: update dependencies",
	"docs: fix broken link",
	"fix: minor cleanup",
	"chore: formatting",
	"ci: bump runner version",
	"docs: improve examples",
	"fix: remove unused code",
	"chore: update config",
	"ci: update cache settings",
	"docs: update contributing guide",
	"chore: housekeeping",
}

const DefaultRef = "refs/nc/latest"
const blobEntryName = "data"

// Client holds credentials and repo identity for GitHub API calls.
type Client struct {
	owner, repo, token string
	http               *http.Client
}

// NewClient parses a GitHub repo URL and returns a ready Client.
// Accepts: https://github.com/owner/repo, github.com/owner/repo, owner/repo
func NewClient(repoURL, token string) (*Client, error) {
	owner, repo, err := parseRepoURL(repoURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		owner: owner,
		repo:  repo,
		token: token,
		http:  &http.Client{},
	}, nil
}

func parseRepoURL(u string) (owner, repo string, err error) {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "github.com/")
	u = strings.TrimSuffix(u, ".git")
	parts := strings.Split(strings.Trim(u, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid repo URL %q — expected owner/repo or https://github.com/owner/repo", u)
	}
	return parts[0], parts[1], nil
}

// Hide stores ciphertext as an orphan git commit under ref.
// Flow: blob → tree → orphan commit → ref (create or force-update).
func (c *Client) Hide(ciphertext []byte, ref string) error {
	blobSHA, err := c.createBlob(ciphertext)
	if err != nil {
		return fmt.Errorf("blob: %w", err)
	}
	treeSHA, err := c.createTree(blobSHA)
	if err != nil {
		return fmt.Errorf("tree: %w", err)
	}
	commitSHA, err := c.createCommit(treeSHA)
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if err := c.setRef(ref, commitSHA); err != nil {
		return fmt.Errorf("ref: %w", err)
	}
	return nil
}

// Reveal fetches and returns the ciphertext stored at ref.
// Flow: ref → commit SHA → tree SHA → blob SHA → raw bytes.
func (c *Client) Reveal(ref string) ([]byte, error) {
	commitSHA, err := c.getRef(ref)
	if err != nil {
		return nil, err
	}
	treeSHA, err := c.getCommitTree(commitSHA)
	if err != nil {
		return nil, fmt.Errorf("commit lookup: %w", err)
	}
	blobSHA, err := c.getTreeBlob(treeSHA)
	if err != nil {
		return nil, fmt.Errorf("tree lookup: %w", err)
	}
	data, err := c.getBlob(blobSHA)
	if err != nil {
		return nil, fmt.Errorf("blob fetch: %w", err)
	}
	return data, nil
}

// Wipe deletes ref from the remote, removing all trace of the dead drop.
func (c *Client) Wipe(ref string) error {
	refPath := strings.TrimPrefix(ref, "refs/")
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/%s", c.owner, c.repo, refPath)
	_, status, err := c.call("DELETE", url, nil)
	if err != nil {
		return err
	}
	if status != 204 {
		return fmt.Errorf("delete ref returned HTTP %d", status)
	}
	return nil
}

// ---------------------------------------------------------------------------
// GitHub Git Data API — low-level calls
// ---------------------------------------------------------------------------

func (c *Client) apiURL(path string) string {
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/git/%s", c.owner, c.repo, path)
}

func (c *Client) call(method, url string, body interface{}) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

func (c *Client) createBlob(data []byte) (string, error) {
	body := map[string]string{
		"content":  base64.StdEncoding.EncodeToString(data),
		"encoding": "base64",
	}
	resp, status, err := c.call("POST", c.apiURL("blobs"), body)
	if err != nil {
		return "", err
	}
	if status != 201 {
		return "", fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		SHA string `json:"sha"`
	}
	return r.SHA, json.Unmarshal(resp, &r)
}

func (c *Client) createTree(blobSHA string) (string, error) {
	body := map[string]interface{}{
		"tree": []map[string]string{{
			"path": blobEntryName,
			"mode": "100644",
			"type": "blob",
			"sha":  blobSHA,
		}},
	}
	resp, status, err := c.call("POST", c.apiURL("trees"), body)
	if err != nil {
		return "", err
	}
	if status != 201 {
		return "", fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		SHA string `json:"sha"`
	}
	return r.SHA, json.Unmarshal(resp, &r)
}

func (c *Client) createCommit(treeSHA string) (string, error) {
	body := map[string]interface{}{
		"message": commitMessages[rand.Intn(len(commitMessages))],
		"tree":    treeSHA,
		"parents": []string{}, // orphan — no parent commits
	}
	resp, status, err := c.call("POST", c.apiURL("commits"), body)
	if err != nil {
		return "", err
	}
	if status != 201 {
		return "", fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		SHA string `json:"sha"`
	}
	return r.SHA, json.Unmarshal(resp, &r)
}

func (c *Client) setRef(ref, sha string) error {
	// Try create first.
	body := map[string]string{"ref": ref, "sha": sha}
	resp, status, err := c.call("POST", c.apiURL("refs"), body)
	if err != nil {
		return err
	}
	if status == 201 {
		return nil
	}
	// Ref already exists — force update.
	if status == 422 {
		refPath := strings.TrimPrefix(ref, "refs/")
		patchURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/%s", c.owner, c.repo, refPath)
		resp, status, err = c.call("PATCH", patchURL, map[string]interface{}{
			"sha":   sha,
			"force": true,
		})
		if err != nil {
			return err
		}
		if status == 200 {
			return nil
		}
	}
	return fmt.Errorf("HTTP %d: %s", status, resp)
}

func (c *Client) getRef(ref string) (string, error) {
	refPath := strings.TrimPrefix(ref, "refs/")
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/%s", c.owner, c.repo, refPath)
	resp, status, err := c.call("GET", url, nil)
	if err != nil {
		return "", err
	}
	if status == 404 {
		return "", fmt.Errorf("ref %q not found — no payload stored at this repo", ref)
	}
	if status != 200 {
		return "", fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	return r.Object.SHA, json.Unmarshal(resp, &r)
}

func (c *Client) getCommitTree(commitSHA string) (string, error) {
	resp, status, err := c.call("GET", c.apiURL("commits/"+commitSHA), nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	return r.Tree.SHA, json.Unmarshal(resp, &r)
}

func (c *Client) getTreeBlob(treeSHA string) (string, error) {
	resp, status, err := c.call("GET", c.apiURL("trees/"+treeSHA), nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		Tree []struct {
			Path string `json:"path"`
			SHA  string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return "", err
	}
	for _, entry := range r.Tree {
		if entry.Path == blobEntryName {
			return entry.SHA, nil
		}
	}
	return "", fmt.Errorf("entry %q not found in tree", blobEntryName)
}

func (c *Client) getBlob(blobSHA string) ([]byte, error) {
	resp, status, err := c.call("GET", c.apiURL("blobs/"+blobSHA), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", status, resp)
	}
	var r struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, err
	}
	// GitHub wraps base64 with newlines every 60 chars.
	cleaned := strings.ReplaceAll(r.Content, "\n", "")
	data, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return data, nil
}
