package grep

import (
	"testing"
)

func TestMatcherKeyPattern(t *testing.T) {
	tests := []struct {
		name       string
		keyPattern string
		data       map[string]interface{}
		wantCount  int
	}{
		{
			name:       "exact key match",
			keyPattern: "CLICKHOUSE_HOST",
			data:       map[string]interface{}{"CLICKHOUSE_HOST": "10.0.0.1", "OTHER": "val"},
			wantCount:  1,
		},
		{
			name:       "glob wildcard match",
			keyPattern: "CLICKHOUSE_*",
			data:       map[string]interface{}{"CLICKHOUSE_HOST": "10.0.0.1", "CLICKHOUSE_PASSWORD": "secret", "OTHER": "val"},
			wantCount:  2,
		},
		{
			name:       "multiple patterns comma-separated",
			keyPattern: "CLICKHOUSE_*,STAT_CLICKHOUSE_*",
			data:       map[string]interface{}{"CLICKHOUSE_HOST": "h", "STAT_CLICKHOUSE_HOST": "sh", "OTHER": "val"},
			wantCount:  2,
		},
		{
			name:       "no match",
			keyPattern: "POSTGRES_*",
			data:       map[string]interface{}{"CLICKHOUSE_HOST": "10.0.0.1"},
			wantCount:  0,
		},
		{
			name:       "case insensitive by default",
			keyPattern: "clickhouse_host",
			data:       map[string]interface{}{"CLICKHOUSE_HOST": "10.0.0.1"},
			wantCount:  1,
		},
		{
			name:       "empty pattern matches all keys",
			keyPattern: "",
			data:       map[string]interface{}{"A": "1", "B": "2"},
			wantCount:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMatcher(tt.keyPattern, "", false)
			matches := m.Match(tt.data, false)
			if len(matches) != tt.wantCount {
				t.Errorf("Match() got %d matches, want %d", len(matches), tt.wantCount)
			}
		})
	}
}

func TestMatcherCaseSensitive(t *testing.T) {
	m := NewMatcher("CLICKHOUSE_HOST", "", true)
	data := map[string]interface{}{"clickhouse_host": "10.0.0.1"}
	matches := m.Match(data, false)
	if len(matches) != 0 {
		t.Errorf("case-sensitive Match() should not match, got %d", len(matches))
	}

	data2 := map[string]interface{}{"CLICKHOUSE_HOST": "10.0.0.1"}
	matches2 := m.Match(data2, false)
	if len(matches2) != 1 {
		t.Errorf("case-sensitive Match() should match exact case, got %d", len(matches2))
	}
}

func TestMatcherValuePattern(t *testing.T) {
	m := NewMatcher("*", "10.200.4.206", false)
	data := map[string]interface{}{
		"HOST":     "10.200.4.206",
		"PASSWORD": "secret123",
		"PORT":     "9000",
	}
	matches := m.Match(data, false)
	if len(matches) != 1 {
		t.Errorf("value pattern Match() got %d matches, want 1", len(matches))
	}
	if len(matches) > 0 && matches[0].Name != "HOST" {
		t.Errorf("matched key = %q, want HOST", matches[0].Name)
	}
}

func TestMatcherShowValues(t *testing.T) {
	m := NewMatcher("HOST", "", false)
	data := map[string]interface{}{"HOST": "10.0.0.1"}

	// Without show values
	matches := m.Match(data, false)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Value != "" {
		t.Errorf("value should be empty when showValues=false, got %q", matches[0].Value)
	}

	// With show values
	matches = m.Match(data, true)
	if matches[0].Value != "10.0.0.1" {
		t.Errorf("value = %q, want 10.0.0.1", matches[0].Value)
	}
}

func TestMatcherDetectsType(t *testing.T) {
	m := NewMatcher("*", "", false)
	data := map[string]interface{}{
		"plain":     "hello",
		"json_blob": `{"host":"10.0.0.1","port":9000}`,
		"number":    float64(42),
		"flag":      true,
	}

	matches := m.Match(data, false)
	typeMap := make(map[string]string)
	for _, mk := range matches {
		typeMap[mk.Name] = mk.Type
	}

	if typeMap["plain"] != "string" {
		t.Errorf("plain type = %q, want string", typeMap["plain"])
	}
	if typeMap["json_blob"] != "json_blob" {
		t.Errorf("json_blob type = %q, want json_blob", typeMap["json_blob"])
	}
	if typeMap["number"] != "number" {
		t.Errorf("number type = %q, want number", typeMap["number"])
	}
	if typeMap["flag"] != "bool" {
		t.Errorf("flag type = %q, want bool", typeMap["flag"])
	}
}

func TestSplitMountPath(t *testing.T) {
	tests := []struct {
		path       string
		wantMount  string
		wantPrefix string
	}{
		{"kv", "kv", ""},
		{"kv/projects", "kv", "projects/"},
		{"kv/projects/", "kv", "projects/"},
		{"kv/projects/back/int", "kv", "projects/back/int/"},
		{"secret", "secret", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			mount, prefix := splitMountPath(tt.path)
			if mount != tt.wantMount {
				t.Errorf("mount = %q, want %q", mount, tt.wantMount)
			}
			if prefix != tt.wantPrefix {
				t.Errorf("prefix = %q, want %q", prefix, tt.wantPrefix)
			}
		})
	}
}
