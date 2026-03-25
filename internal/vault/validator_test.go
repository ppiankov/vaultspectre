package vault

import "testing"

func TestConvertToKVv2Path(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "standard kv v1 path gets /data/ inserted",
			path: "secret/prod/app",
			want: "secret/data/prod/app",
		},
		{
			name: "deeper kv v1 path",
			path: "secret/production/database/creds",
			want: "secret/data/production/database/creds",
		},
		{
			name: "custom mount with subpath",
			path: "kv/myapp/config",
			want: "kv/data/myapp/config",
		},
		{
			name: "already has /data/ segment unchanged",
			path: "secret/data/prod/app",
			want: "secret/data/prod/app",
		},
		{
			name: "already has /metadata/ segment unchanged",
			path: "secret/metadata/prod/app",
			want: "secret/metadata/prod/app",
		},
		{
			name: "sys/ prefix unchanged",
			path: "sys/mounts",
			want: "sys/mounts",
		},
		{
			name: "auth/ prefix unchanged",
			path: "auth/token/lookup-self",
			want: "auth/token/lookup-self",
		},
		{
			name: "cubbyhole/ prefix unchanged",
			path: "cubbyhole/my-secret",
			want: "cubbyhole/my-secret",
		},
		{
			name: "identity/ prefix unchanged",
			path: "identity/entity/name/app",
			want: "identity/entity/name/app",
		},
		{
			name: "single segment path unchanged",
			path: "secret",
			want: "secret",
		},
		{
			name: "empty string unchanged",
			path: "",
			want: "",
		},
		{
			name: "two segment path gets /data/ inserted",
			path: "secret/mykey",
			want: "secret/data/mykey",
		},
		{
			name: "path segment named data not treated as KV v2 marker",
			path: "kv/projects/data/int/myservice",
			want: "kv/data/projects/data/int/myservice",
		},
		{
			name: "deeper data segment not confused with KV v2",
			path: "secret/apps/data/config",
			want: "secret/data/apps/data/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToKVv2Path(tt.path)
			if got != tt.want {
				t.Errorf("convertToKVv2Path(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseKVv2Path(t *testing.T) {
	tests := []struct {
		name       string
		fullPath   string
		wantMount  string
		wantSecret string
	}{
		{
			name:       "standard kv v2 path",
			fullPath:   "secret/data/prod/api/key",
			wantMount:  "secret",
			wantSecret: "prod/api/key",
		},
		{
			name:       "simple kv v2 path",
			fullPath:   "kv/data/myapp",
			wantMount:  "kv",
			wantSecret: "myapp",
		},
		{
			name:       "fewer than 3 parts returns empty",
			fullPath:   "secret/data",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "single segment returns empty",
			fullPath:   "secret",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "no data segment returns empty",
			fullPath:   "secret/prod/api/key",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "empty string returns empty",
			fullPath:   "",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "deep secret path after data",
			fullPath:   "secret/data/a/b/c/d",
			wantMount:  "secret",
			wantSecret: "a/b/c/d",
		},
		{
			name:       "data as deeper segment not treated as KV v2 marker",
			fullPath:   "kv/projects/data/int/myservice",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "data in third position not matched",
			fullPath:   "secret/apps/data/config",
			wantMount:  "",
			wantSecret: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMount, gotSecret := parseKVv2Path(tt.fullPath)
			if gotMount != tt.wantMount {
				t.Errorf("parseKVv2Path(%q) mount = %q, want %q", tt.fullPath, gotMount, tt.wantMount)
			}
			if gotSecret != tt.wantSecret {
				t.Errorf("parseKVv2Path(%q) secret = %q, want %q", tt.fullPath, gotSecret, tt.wantSecret)
			}
		})
	}
}
