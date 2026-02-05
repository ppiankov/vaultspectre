package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Scanner scans repositories for Vault secret references
type Scanner struct {
	repoPath string
	patterns []*Pattern
}

// Reference represents a discovered Vault secret reference
type Reference struct {
	Path         string `json:"path"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Type         string `json:"type"`
	Status       string `json:"status,omitempty"`
	ErrorMsg     string `json:"error_msg,omitempty"`
	IsStale      bool   `json:"is_stale,omitempty"`
	LastAccessed string `json:"last_accessed,omitempty"`
}

// New creates a new scanner for the given repository path
func New(repoPath string) *Scanner {
	return &Scanner{
		repoPath: repoPath,
		patterns: GetPatterns(),
	}
}

// Scan performs the repository scan and returns all found references
func (s *Scanner) Scan() ([]Reference, error) {
	var references []Reference
	seen := make(map[string]bool) // Deduplication

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		base := filepath.Base(path)

		// Skip directories and hidden files/directories (but not the root "." or "..")
		if info.IsDir() {
			if strings.HasPrefix(base, ".") && base != "." && base != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasPrefix(base, ".") {
			return nil
		}

		// Skip binary files and large files
		if info.Size() > 10*1024*1024 { // Skip files > 10MB
			return nil
		}

		// Check if file should be scanned based on extension
		if !shouldScanFile(path) {
			return nil
		}

		// Scan file
		refs, err := s.scanFile(path)
		if err != nil {
			// Log warning but continue
			return nil
		}

		// Deduplicate references
		for _, ref := range refs {
			key := ref.Path + "|" + ref.File
			if !seen[key] {
				seen[key] = true
				references = append(references, ref)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return references, nil
}

func (s *Scanner) scanFile(path string) ([]Reference, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var references []Reference
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, pattern := range s.patterns {
			matches := pattern.Regex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 {
					secretPath := cleanSecretPath(match[1])
					if isValidVaultPath(secretPath) {
						relPath, _ := filepath.Rel(s.repoPath, path)
						ref := Reference{
							Path: secretPath,
							File: relPath,
							Line: lineNum,
							Type: pattern.Type,
						}
						// Mark dynamic paths so they can be handled separately
						if isDynamicPath(secretPath) {
							ref.Status = "dynamic"
						}
						references = append(references, ref)
					}
				}
			}
		}
	}

	return references, scanner.Err()
}

func shouldScanFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Scan these extensions
	validExts := map[string]bool{
		".yml":   true,
		".yaml":  true,
		".py":    true,
		".sh":    true,
		".bash":  true,
		".tf":    true,
		".hcl":   true,
		".j2":    true,
		".jinja": true,
		".txt":   true,
		".env":   true,
		".conf":  true,
		".cfg":   true,
		".ini":   true,
		".toml":  true,
		".json":  true,
		".go":    true,
		".rb":    true,
		".java":  true,
		".js":    true,
		".ts":    true,
	}

	// Scan files without extension that might be scripts
	if ext == "" {
		return strings.HasPrefix(base, "dockerfile") ||
			base == "makefile" ||
			base == "rakefile"
	}

	return validExts[ext]
}

func cleanSecretPath(path string) string {
	// Remove quotes and whitespace
	path = strings.Trim(path, `"' `)
	// Normalize path separators
	path = strings.TrimPrefix(path, "/")
	return path
}

func isValidVaultPath(path string) bool {
	// Basic validation: must contain at least one /
	if !strings.Contains(path, "/") {
		return false
	}

	// Skip if it looks like a URL
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return false
	}

	// Must not be too short or too long
	if len(path) < 3 || len(path) > 512 {
		return false
	}

	return true
}

func isDynamicPath(path string) bool {
	// Check for template variables
	return strings.Contains(path, "{{") ||
		strings.Contains(path, "${") ||
		strings.Contains(path, "$")
}
