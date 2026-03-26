package grep

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/ppiankov/vaultspectre/internal/verify"
)

// readJob is a path to be read by a worker goroutine.
type readJob struct {
	path string
}

// Walker recursively walks a Vault KV tree and applies a matcher to each secret.
type Walker struct {
	client       *vault.Client
	matcher      *Matcher
	showValues   bool
	maxDepth     int // 0 = unlimited
	workers      int
	dryRun       bool
	kvVersion    int // 1 or 2, 0 = auto-detect
	verifyFormat bool
}

// WalkerConfig configures the walker.
type WalkerConfig struct {
	ShowValues   bool
	MaxDepth     int
	Workers      int
	DryRun       bool
	KVVersion    int
	VerifyFormat bool
}

// NewWalker creates a new recursive Vault walker.
func NewWalker(client *vault.Client, matcher *Matcher, cfg WalkerConfig) *Walker {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 10
	}
	return &Walker{
		client:       client,
		matcher:      matcher,
		showValues:   cfg.ShowValues,
		maxDepth:     cfg.MaxDepth,
		workers:      workers,
		dryRun:       cfg.DryRun,
		kvVersion:    cfg.KVVersion,
		verifyFormat: cfg.VerifyFormat,
	}
}

// Walk starts the recursive walk from the given path and returns all matches.
func (w *Walker) Walk(basePath string) (*GrepResult, error) {
	// Normalize base path
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		basePath = "kv"
	}

	// Determine mount and KV version
	mount, prefix := splitMountPath(basePath)

	result := &GrepResult{}
	var mu sync.Mutex
	var scanned atomic.Int64
	var skipped atomic.Int64

	jobs := make(chan readJob, w.workers*2)
	var wg sync.WaitGroup

	// Start worker pool for reading secrets
	for range w.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				scanned.Add(1)

				if w.dryRun {
					mu.Lock()
					result.Matches = append(result.Matches, PathMatch{Path: job.path})
					mu.Unlock()
					continue
				}

				// Read the secret
				readPath := job.path
				if w.kvVersion == 2 || w.kvVersion == 0 {
					// For KV v2, read via data/ path
					readPath = mount + "/data/" + strings.TrimPrefix(job.path, mount+"/")
				}

				secret, err := w.client.Read(readPath)
				if err != nil {
					if isPermissionError(err) {
						skipped.Add(1)
						slog.Warn("permission denied, skipping", "path", job.path)
						continue
					}
					slog.Debug("failed to read secret", "path", job.path, "error", sanitizeError(err))
					continue
				}

				if secret == nil || secret.Data == nil {
					continue
				}

				// For KV v2, the actual data is nested under "data" key
				data := secret.Data
				if nested, ok := data["data"].(map[string]interface{}); ok {
					data = nested
				}

				matches := w.matcher.Match(data, w.showValues)
				if len(matches) > 0 {
					pm := PathMatch{
						Path: job.path,
						Keys: matches,
					}

					// Run format verification if enabled
					if w.verifyFormat {
						fv := verify.NewFormatVerifier()
						vr := fv.Verify(job.path, data, 5*time.Second)
						if vr.Status == verify.StatusFormatError {
							pm.FormatIssues = vr.Details
						}
					}

					mu.Lock()
					result.Matches = append(result.Matches, pm)
					mu.Unlock()
				}
			}
		}()
	}

	// Recursive listing
	var walkErr error
	w.walkRecursive(mount, prefix, 0, jobs, &skipped, &walkErr)
	close(jobs)
	wg.Wait()

	result.TotalScanned = int(scanned.Load())
	result.TotalSkipped = int(skipped.Load())
	result.MatchCount = len(result.Matches)

	if walkErr != nil {
		return result, walkErr
	}

	return result, nil
}

// WalkPaths reads specific paths (from stdin) instead of recursive walking.
func (w *Walker) WalkPaths(paths []string) (*GrepResult, error) {
	result := &GrepResult{}

	// Determine mount from first path
	mount := ""
	if len(paths) > 0 {
		mount, _ = splitMountPath(paths[0])
	}

	for _, path := range paths {
		if w.dryRun {
			result.Matches = append(result.Matches, PathMatch{Path: path})
			result.TotalScanned++
			continue
		}

		// Read the secret
		if m, _ := splitMountPath(path); m != "" {
			mount = m
		}
		kvReadPath := mount + "/data/" + strings.TrimPrefix(path, mount+"/")

		secret, err := w.client.Read(kvReadPath)
		if err != nil {
			if isPermissionError(err) {
				result.TotalSkipped++
				slog.Warn("permission denied, skipping", "path", path)
				continue
			}
			// Try direct path (KV v1)
			secret, err = w.client.Read(path)
			if err != nil {
				slog.Debug("failed to read secret", "path", path, "error", sanitizeError(err))
				result.TotalScanned++
				continue
			}
		}
		result.TotalScanned++

		if secret == nil || secret.Data == nil {
			continue
		}

		data := secret.Data
		if nested, ok := data["data"].(map[string]interface{}); ok {
			data = nested
		}

		matches := w.matcher.Match(data, w.showValues)
		if len(matches) > 0 {
			pm := PathMatch{Path: path, Keys: matches}
			if w.verifyFormat {
				fv := verify.NewFormatVerifier()
				vr := fv.Verify(path, data, 5*time.Second)
				if vr.Status == verify.StatusFormatError {
					pm.FormatIssues = vr.Details
				}
			}
			result.Matches = append(result.Matches, pm)
		}
	}

	result.MatchCount = len(result.Matches)
	return result, nil
}

func (w *Walker) walkRecursive(mount, prefix string, depth int, jobs chan<- readJob, skipped *atomic.Int64, walkErr *error) {
	if w.maxDepth > 0 && depth >= w.maxDepth {
		return
	}

	// List path: for KV v2, list via metadata/
	listPath := mount + "/metadata/"
	if prefix != "" {
		listPath += prefix
	}

	// Also try direct list (KV v1 or non-KV mounts)
	keys, err := w.client.List(listPath)
	if err != nil || keys == nil {
		// Try without metadata/ prefix (KV v1)
		directPath := mount + "/"
		if prefix != "" {
			directPath += prefix
		}
		keys, err = w.client.List(directPath)
		if err != nil {
			if isPermissionError(err) {
				skipped.Add(1)
				slog.Warn("permission denied on list, skipping subtree", "path", directPath)
				return
			}
			// Only set walkErr for non-permission errors at root level
			if depth == 0 {
				*walkErr = fmt.Errorf("failed to list %s: %w", directPath, err)
			}
			return
		}
	}

	for _, key := range keys {
		fullPath := mount + "/"
		if prefix != "" {
			fullPath += prefix
		}

		if strings.HasSuffix(key, "/") {
			// Directory — recurse
			subPrefix := prefix + key
			if prefix == "" {
				subPrefix = key
			}
			w.walkRecursive(mount, subPrefix, depth+1, jobs, skipped, walkErr)
		} else {
			// Secret — queue for reading
			secretPath := fullPath + key
			jobs <- readJob{path: secretPath}
		}
	}
}

// splitMountPath splits "kv/projects/data" into ("kv", "projects/data/").
// If no slash, treats entire string as mount with empty prefix.
func splitMountPath(path string) (string, string) {
	idx := strings.IndexByte(path, '/')
	if idx < 0 {
		return path, ""
	}
	mount := path[:idx]
	prefix := path[idx+1:]
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return mount, prefix
}

func isPermissionError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "403")
}

// sanitizeError strips potentially sensitive data from Vault API error messages.
func sanitizeError(err error) string {
	msg := err.Error()
	// Truncate overly long error messages that may contain response bodies
	if len(msg) > 200 {
		msg = msg[:200] + "...[truncated]"
	}
	return msg
}
