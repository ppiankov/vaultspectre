package vault

import (
	"fmt"
	"os"

	vault "github.com/hashicorp/vault/api"
)

// AuthMethod identifies a Vault authentication method.
type AuthMethod string

const (
	AuthToken      AuthMethod = "token"
	AuthAppRole    AuthMethod = "approle"
	AuthKubernetes AuthMethod = "kubernetes"
)

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Method     AuthMethod
	Token      string // For AuthToken
	RoleID     string // For AuthAppRole
	SecretID   string // For AuthAppRole
	K8sRole    string // For AuthKubernetes
	K8sJWTPath string // For AuthKubernetes (default: /var/run/secrets/kubernetes.io/serviceaccount/token)
	MountPath  string // Auth mount path (default: "approle" or "kubernetes")
}

// Authenticate obtains a Vault token using the configured auth method
// and sets it on the client.
func Authenticate(client *vault.Client, cfg AuthConfig) error {
	switch cfg.Method {
	case AuthToken, "":
		if cfg.Token == "" {
			return fmt.Errorf("vault token is required for token auth")
		}
		client.SetToken(cfg.Token)
		return nil

	case AuthAppRole:
		return authenticateAppRole(client, cfg)

	case AuthKubernetes:
		return authenticateKubernetes(client, cfg)

	default:
		return fmt.Errorf("unsupported auth method: %s", cfg.Method)
	}
}

func authenticateAppRole(client *vault.Client, cfg AuthConfig) error {
	if cfg.RoleID == "" {
		return fmt.Errorf("role-id is required for AppRole auth")
	}
	if cfg.SecretID == "" {
		return fmt.Errorf("secret-id is required for AppRole auth")
	}

	mountPath := cfg.MountPath
	if mountPath == "" {
		mountPath = "approle"
	}

	secret, err := client.Logical().Write(
		fmt.Sprintf("auth/%s/login", mountPath),
		map[string]interface{}{
			"role_id":   cfg.RoleID,
			"secret_id": cfg.SecretID,
		},
	)
	if err != nil {
		return fmt.Errorf("approle login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("approle login returned no auth data")
	}

	client.SetToken(secret.Auth.ClientToken)
	return nil
}

func authenticateKubernetes(client *vault.Client, cfg AuthConfig) error {
	if cfg.K8sRole == "" {
		return fmt.Errorf("k8s-role is required for Kubernetes auth")
	}

	jwtPath := cfg.K8sJWTPath
	if jwtPath == "" {
		jwtPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	jwt, err := os.ReadFile(jwtPath)
	if err != nil {
		return fmt.Errorf("failed to read JWT from %s: %w", jwtPath, err)
	}

	mountPath := cfg.MountPath
	if mountPath == "" {
		mountPath = "kubernetes"
	}

	secret, err := client.Logical().Write(
		fmt.Sprintf("auth/%s/login", mountPath),
		map[string]interface{}{
			"role": cfg.K8sRole,
			"jwt":  string(jwt),
		},
	)
	if err != nil {
		return fmt.Errorf("kubernetes login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("kubernetes login returned no auth data")
	}

	client.SetToken(secret.Auth.ClientToken)
	return nil
}

// ValidAuthMethod checks if the given string is a valid auth method.
func ValidAuthMethod(method string) bool {
	switch AuthMethod(method) {
	case AuthToken, AuthAppRole, AuthKubernetes:
		return true
	default:
		return false
	}
}
