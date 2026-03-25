package vault

import "testing"

func TestValidAuthMethod(t *testing.T) {
	tests := []struct {
		method string
		valid  bool
	}{
		{"token", true},
		{"approle", true},
		{"kubernetes", true},
		{"", false},
		{"ldap", false},
		{"oidc", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := ValidAuthMethod(tt.method); got != tt.valid {
				t.Errorf("ValidAuthMethod(%q) = %v, want %v", tt.method, got, tt.valid)
			}
		})
	}
}

func TestAuthenticateTokenMissing(t *testing.T) {
	err := Authenticate(nil, AuthConfig{Method: AuthToken, Token: ""})
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestAuthenticateAppRoleMissingFields(t *testing.T) {
	err := Authenticate(nil, AuthConfig{Method: AuthAppRole, RoleID: "", SecretID: "s"})
	if err == nil {
		t.Error("expected error for missing role_id")
	}

	err = Authenticate(nil, AuthConfig{Method: AuthAppRole, RoleID: "r", SecretID: ""})
	if err == nil {
		t.Error("expected error for missing secret_id")
	}
}

func TestAuthenticateKubernetesMissingRole(t *testing.T) {
	err := Authenticate(nil, AuthConfig{Method: AuthKubernetes, K8sRole: ""})
	if err == nil {
		t.Error("expected error for missing k8s-role")
	}
}

func TestAuthenticateUnsupportedMethod(t *testing.T) {
	err := Authenticate(nil, AuthConfig{Method: "ldap"})
	if err == nil {
		t.Error("expected error for unsupported method")
	}
}
