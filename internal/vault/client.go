package vault

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

// Config holds Vault client configuration
type Config struct {
	Address   string
	Token     string
	Namespace string
}

// Client wraps the Vault API client
type Client struct {
	client *vault.Client
	config Config
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

	return &Client{
		client: client,
		config: cfg,
	}, nil
}

// Read reads a secret from the given path
func (c *Client) Read(path string) (*vault.Secret, error) {
	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// GetMetadata gets metadata for a KV v2 secret
func (c *Client) GetMetadata(mount, path string) (*vault.Secret, error) {
	metadataPath := fmt.Sprintf("%s/metadata/%s", mount, path)
	return c.Read(metadataPath)
}

// GetClient returns the underlying Vault API client
func (c *Client) GetClient() *vault.Client {
	return c.client
}
