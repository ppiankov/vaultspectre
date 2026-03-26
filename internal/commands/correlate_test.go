package commands

import (
	"testing"

	"github.com/ppiankov/vaultspectre/internal/grep"
)

func TestCorrelateAllClassifications(t *testing.T) {
	// Set the key field for matching
	correlateKeyField = "CLICKHOUSE_USER"

	vaultResult := grep.GrepResult{
		Matches: []grep.PathMatch{
			{
				Path: "kv/projects/ads/int/ads-stat",
				Keys: []grep.MatchedKey{
					{Name: "CLICKHOUSE_USER", Value: "ads_user"},
					{Name: "CLICKHOUSE_PASSWORD", Value: "secret"},
				},
			},
			{
				Path: "kv/projects/rnd/int/reco-go",
				Keys: []grep.MatchedKey{
					{Name: "CLICKHOUSE_USER", Value: "inactive_user"},
				},
			},
			{
				Path: "kv/projects/old/int/removed-svc",
				Keys: []grep.MatchedKey{
					{Name: "CLICKHOUSE_USER", Value: "stale_user"},
				},
			},
		},
	}

	chReport := ClickSpectreReport{
		Users: []ClickSpectreUser{
			{Username: "ads_user", QueryCount: 14203, IsActive: true, LastSeen: "2026-03-25"},
			{Username: "signoz", QueryCount: 1204, IsActive: true, LastSeen: "2026-03-25"},
			{Username: "inactive_user", QueryCount: 0, IsActive: false},
			{Username: "orphan_user", QueryCount: 0, IsActive: false},
		},
	}

	result := correlate(vaultResult, chReport)

	if result.Summary.ActiveWithVault != 1 {
		t.Errorf("active_with_vault = %d, want 1", result.Summary.ActiveWithVault)
	}
	if result.Summary.ActiveNoVault != 1 {
		t.Errorf("active_no_vault = %d, want 1 (signoz)", result.Summary.ActiveNoVault)
	}
	if result.Summary.InactiveVault != 1 {
		t.Errorf("inactive_with_vault = %d, want 1 (inactive_user)", result.Summary.InactiveVault)
	}
	if result.Summary.InactiveNoVault != 1 {
		t.Errorf("inactive_no_vault = %d, want 1 (orphan_user)", result.Summary.InactiveNoVault)
	}
	if result.Summary.VaultOnly != 1 {
		t.Errorf("vault_only = %d, want 1 (stale_user)", result.Summary.VaultOnly)
	}

	if len(result.Users) != 5 {
		t.Errorf("total users = %d, want 5", len(result.Users))
	}
}

func TestCorrelateNoUsers(t *testing.T) {
	correlateKeyField = "CLICKHOUSE_USER"

	result := correlate(grep.GrepResult{}, ClickSpectreReport{})

	if len(result.Users) != 0 {
		t.Errorf("expected 0 users, got %d", len(result.Users))
	}
	if !result.Summary.isEmpty() {
		t.Error("empty correlation should have zero summary")
	}
}

func (s CorrelateSummary) isEmpty() bool {
	return s.ActiveWithVault == 0 && s.ActiveNoVault == 0 &&
		s.InactiveVault == 0 && s.InactiveNoVault == 0 && s.VaultOnly == 0
}

func TestCorrelateMultipleVaultPaths(t *testing.T) {
	correlateKeyField = "CLICKHOUSE_USER"

	vaultResult := grep.GrepResult{
		Matches: []grep.PathMatch{
			{Path: "kv/ads/int", Keys: []grep.MatchedKey{{Name: "CLICKHOUSE_USER", Value: "ads_user"}}},
			{Path: "kv/ads/stress", Keys: []grep.MatchedKey{{Name: "CLICKHOUSE_USER", Value: "ads_user"}}},
		},
	}

	chReport := ClickSpectreReport{
		Users: []ClickSpectreUser{
			{Username: "ads_user", QueryCount: 100, IsActive: true},
		},
	}

	result := correlate(vaultResult, chReport)

	if len(result.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(result.Users))
	}
	if len(result.Users[0].VaultPaths) != 2 {
		t.Errorf("vault paths = %d, want 2", len(result.Users[0].VaultPaths))
	}
}
