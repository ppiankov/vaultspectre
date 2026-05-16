package mcp

import (
	"testing"
	"time"
)

func TestNewServer_NonNil(t *testing.T) {
	cfg := ServerConfig{
		VaultAddr:  "https://vault.example.com",
		VaultToken: "test-token",
		Namespace:  "",
		Timeout:    5 * time.Second,
		Version:    "test",
	}
	s := NewServer(cfg)
	if s == nil {
		t.Error("NewServer should return a non-nil server")
	}
}

func TestLsTool_NameSet(t *testing.T) {
	tool := lsTool()
	if tool.Name != "vaultspectre_ls" {
		t.Errorf("ls tool name: got %q, want vaultspectre_ls", tool.Name)
	}
}

func TestGrepTool_NameSet(t *testing.T) {
	tool := grepTool()
	if tool.Name != "vaultspectre_grep" {
		t.Errorf("grep tool name: got %q, want vaultspectre_grep", tool.Name)
	}
}

func TestCountTool_NameSet(t *testing.T) {
	tool := countTool()
	if tool.Name != "vaultspectre_count" {
		t.Errorf("count tool name: got %q, want vaultspectre_count", tool.Name)
	}
}

func TestDoctorTool_NameSet(t *testing.T) {
	tool := doctorTool()
	if tool.Name != "vaultspectre_doctor" {
		t.Errorf("doctor tool name: got %q, want vaultspectre_doctor", tool.Name)
	}
}
