package grep

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// Matcher checks secret keys and values against glob patterns.
type Matcher struct {
	keyPatterns   []string
	valuePatterns []string
	caseSensitive bool
}

// NewMatcher creates a matcher from comma-separated pattern strings.
func NewMatcher(keyPattern, valuePattern string, caseSensitive bool) *Matcher {
	m := &Matcher{caseSensitive: caseSensitive}

	if keyPattern != "" {
		for _, p := range strings.Split(keyPattern, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				m.keyPatterns = append(m.keyPatterns, trimmed)
			}
		}
	}
	if valuePattern != "" {
		for _, p := range strings.Split(valuePattern, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				m.valuePatterns = append(m.valuePatterns, trimmed)
			}
		}
	}

	return m
}

// Match checks a secret's data map and returns matched keys.
// Returns nil if no keys match.
func (m *Matcher) Match(data map[string]interface{}, showValues bool) []MatchedKey {
	var matches []MatchedKey

	for key, val := range data {
		keyStr := key
		if !m.caseSensitive {
			keyStr = strings.ToLower(keyStr)
		}

		keyMatch := len(m.keyPatterns) == 0 // No key pattern means match all
		for _, pattern := range m.keyPatterns {
			p := pattern
			if !m.caseSensitive {
				p = strings.ToLower(p)
			}
			if matched, _ := filepath.Match(p, keyStr); matched {
				keyMatch = true
				break
			}
		}

		if !keyMatch {
			continue
		}

		valStr := formatValue(val)
		valType := detectType(val)

		// If value patterns specified, check them too (AND with key match)
		if len(m.valuePatterns) > 0 {
			checkVal := valStr
			if !m.caseSensitive {
				checkVal = strings.ToLower(checkVal)
			}
			valueMatch := false
			for _, pattern := range m.valuePatterns {
				p := pattern
				if !m.caseSensitive {
					p = strings.ToLower(p)
				}
				// Use Contains for value matching (more useful than glob for values)
				if strings.Contains(checkVal, p) {
					valueMatch = true
					break
				}
				if matched, _ := filepath.Match(p, checkVal); matched {
					valueMatch = true
					break
				}
			}
			if !valueMatch {
				continue
			}
		}

		mk := MatchedKey{
			Name: key,
			Type: valType,
		}
		if showValues {
			mk.Value = valStr
		}
		matches = append(matches, mk)
	}

	return matches
}

func formatValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "<unreadable>"
		}
		return string(b)
	}
}

func detectType(val interface{}) string {
	switch v := val.(type) {
	case string:
		// Check if string is actually a JSON object
		if strings.HasPrefix(strings.TrimSpace(v), "{") {
			var obj map[string]interface{}
			if json.Unmarshal([]byte(v), &obj) == nil {
				return "json_blob"
			}
		}
		return "string"
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	case float64:
		return "number"
	case bool:
		return "bool"
	default:
		return "unknown"
	}
}
