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
	Path         string   `json:"path"`           // Original extracted path (may contain variables)
	ResolvedPath string   `json:"resolved_path"`  // Path after variable resolution
	File         string   `json:"file"`
	Line         int      `json:"line"`
	Type         string   `json:"type"`
	Status       string   `json:"status,omitempty"`
	ErrorMsg     string   `json:"error_msg,omitempty"`
	IsStale      bool     `json:"is_stale,omitempty"`
	LastAccessed string   `json:"last_accessed,omitempty"`
	Variables    []string `json:"variables,omitempty"`    // Variables that need resolution
	SkipReason   string   `json:"skip_reason,omitempty"`  // Why path was skipped (policy wildcards only)
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
	seen := make(map[string]bool)

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		base := filepath.Base(path)

		if info.IsDir() {
			if strings.HasPrefix(base, ".") && base != "." && base != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasPrefix(base, ".") {
			return nil
		}

		if info.Size() > 10*1024*1024 {
			return nil
		}

		if !shouldScanFile(path) {
			return nil
		}

		refs, err := s.scanFile(path)
		if err != nil {
			return nil
		}

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

		// ROOTOPS: Skip YAML variable definitions (not references)
		if isYAMLVariableDefinition(line) {
			continue
		}

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

						// ROOTOPS: Classify at extraction
						if containsWildcard(secretPath) {
							// Policy wildcards cannot be resolved - skip these
							ref.Status = "skipped_policy"
							ref.SkipReason = "Wildcard pattern (Vault policy)"
						} else if containsAnsibleVar(secretPath) {
							// Needs variable resolution
							ref.Status = "needs_resolution"
							ref.Variables = extractAnsibleVars(secretPath)
							ref.ResolvedPath = "" // Will be set during resolution
						} else {
							// Static path - ready for validation
							ref.Status = "pending_validation"
							ref.ResolvedPath = secretPath
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

	// ROOTOPS: Refuse example files
	if isExampleFile(base) {
		return false
	}

	// ROOTOPS: Refuse policy files (they contain wildcards by design)
	if isPolicyFile(ext, base) {
		return false
	}

	validExts := map[string]bool{
		".yml": true, ".yaml": true, ".py": true, ".sh": true,
		".bash": true, ".tf": true, ".j2": true, ".jinja": true,
		".txt": true, ".env": true, ".conf": true, ".cfg": true,
		".ini": true, ".toml": true, ".json": true, ".go": true,
		".rb": true, ".java": true, ".js": true, ".ts": true,
	}

	if ext == "" {
		return strings.HasPrefix(base, "dockerfile") ||
			base == "makefile" || base == "rakefile"
	}

	return validExts[ext]
}

func isExampleFile(basename string) bool {
	patterns := []string{
		"_example.", ".example.", "_sample.", ".sample.",
		"_template.", ".template.", "example_", "sample_", "template_",
	}
	for _, p := range patterns {
		if strings.Contains(basename, p) {
			return true
		}
	}
	return false
}

func isPolicyFile(ext, basename string) bool {
	if ext == ".hcl" {
		return true
	}
	if strings.Contains(basename, "policy") && (ext == ".json" || ext == "") {
		return true
	}
	return false
}

func cleanSecretPath(path string) string {
	path = strings.Trim(path, `"' `)
	path = strings.TrimPrefix(path, "/")
	return path
}

func isValidVaultPath(path string) bool {
	if !strings.Contains(path, "/") {
		return false
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return false
	}
	if len(path) < 3 || len(path) > 512 {
		return false
	}
	return true
}

func containsAnsibleVar(path string) bool {
	return strings.Contains(path, "{{") && strings.Contains(path, "}}")
}

// isYAMLVariableDefinition checks if a line is a YAML variable definition
// Variable definitions should not be extracted as Vault path references
// Examples:
//   vault_secret_path: "secret/data/production/..."  <- variable definition (skip)
//   postgres_cluster_name: "mydb"                    <- variable definition (skip)
//   vault_keeper_secret: "{{ lookup(...) }}"         <- set_fact/task (don't skip - has lookup)
func isYAMLVariableDefinition(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Skip comments
	if strings.HasPrefix(trimmed, "#") {
		return false
	}

	// Check if line matches pattern: identifier: value
	colonIdx := strings.Index(trimmed, ":")
	if colonIdx == -1 {
		return false
	}

	beforeColon := trimmed[:colonIdx]
	afterColon := trimmed[colonIdx+1:]

	// If there's a lookup() in the value part, it's a reference (Ansible set_fact), not a definition
	if strings.Contains(afterColon, "lookup(") {
		return false
	}

	// If there's {{ }} Jinja template in the value, and it's NOT just setting a vault path variable,
	// it's likely a task variable assignment, not a simple definition
	if strings.Contains(afterColon, "{{") && !strings.Contains(afterColon, "vault") && !strings.Contains(afterColon, "secret") {
		return false
	}

	// If before colon contains function calls or special chars, it's not a simple variable definition
	if strings.Contains(beforeColon, "(") {
		return false
	}

	beforeColon = strings.TrimSpace(beforeColon)
	if len(beforeColon) == 0 {
		return false
	}

	// Check if it's a valid YAML key (simple identifier)
	for _, ch := range beforeColon {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			 (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return false
		}
	}

	// Additional check: if the key is specifically vault_secret_path or *_path and value is a quoted string
	// with secret/data/ in it, it's a variable definition
	if (strings.HasSuffix(beforeColon, "_path") || strings.HasSuffix(beforeColon, "_secret_path")) &&
	   (strings.Contains(afterColon, "secret/data/") || strings.Contains(afterColon, "kv/data/")) {
		return true
	}

	// Don't filter other cases - let them be extracted
	return false
}

func extractAnsibleVars(path string) []string {
	var vars []string
	start := 0
	for {
		startIdx := strings.Index(path[start:], "{{")
		if startIdx == -1 {
			break
		}
		startIdx += start
		endIdx := strings.Index(path[startIdx:], "}}")
		if endIdx == -1 {
			break
		}
		endIdx += startIdx
		varExpr := strings.TrimSpace(path[startIdx+2 : endIdx])
		// Handle complex expressions: {{ vault_secret_path }}, {{ foo.bar }}, {{ baz | default('x') }}
		varName := strings.Split(varExpr, "|")[0]  // Remove filters
		varName = strings.Split(varName, ".")[0]   // Remove property access
		varName = strings.TrimSpace(varName)
		if varName != "" {
			vars = append(vars, varName)
		}
		start = endIdx + 2
	}
	return vars
}

func containsWildcard(path string) bool {
	return strings.Contains(path, "*") || strings.Contains(path, "+")
}

func isDynamicPath(path string) bool {
	return strings.Contains(path, "{{") ||
		strings.Contains(path, "${") ||
		strings.Contains(path, "$")
}
