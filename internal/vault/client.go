package vault

import (
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

const defaultTimeout = 30 * time.Second

// Config holds Vault client configuration
type Config struct {
	Address   string
	Token     string
	Namespace string
	Timeout   time.Duration
}

// Client wraps the Vault API client with retry support
type Client struct {
	client  *vault.Client
	config  Config
	timeout time.Duration
}

// NewClient creates a new Vault client
func NewClient(cfg Config) (*Client, error) {
	config := vault.DefaultConfig()
	config.Address = cfg.Address

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	client.SetToken(cfg.Token)

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	return &Client{
		client:  client,
		config:  cfg,
		timeout: timeout,
	}, nil
}

// Read reads a secret from the given path with automatic retry for transient errors.
func (c *Client) Read(path string) (*vault.Secret, error) {
	var result *vault.Secret
	err := withRetry(c.timeout, func() error {
		secret, readErr := c.client.Logical().Read(path)
		if readErr != nil {
			return readErr
		}
		result = secret
		return nil
	})
	return result, err
}

// GetMetadata gets metadata for a KV v2 secret
func (c *Client) GetMetadata(mount, path string) (*vault.Secret, error) {
	metadataPath := fmt.Sprintf("%s/metadata/%s", mount, path)
	return c.Read(metadataPath)
}

// List lists secrets at a given path. Keys ending in "/" are directories.
func (c *Client) List(path string) ([]string, error) {
	var result *vault.Secret
	err := withRetry(c.timeout, func() error {
		secret, listErr := c.client.Logical().List(path)
		if listErr != nil {
			return listErr
		}
		result = secret
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result == nil || result.Data == nil {
		return nil, nil
	}

	keysRaw, ok := result.Data["keys"]
	if !ok {
		return nil, nil
	}

	keysList, ok := keysRaw.([]interface{})
	if !ok {
		return nil, nil
	}

	keys := make([]string, 0, len(keysList))
	for _, k := range keysList {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}
	return keys, nil
}

// GetClient returns the underlying Vault API client
func (c *Client) GetClient() *vault.Client {
	return c.client
}
