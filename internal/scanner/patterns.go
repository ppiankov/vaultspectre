package scanner

import "regexp"

// Pattern represents a regex pattern for finding Vault references
type Pattern struct {
	Name  string
	Type  string
	Regex *regexp.Regexp
}

// GetPatterns returns all configured patterns for finding Vault secret references
func GetPatterns() []*Pattern {
	return []*Pattern{
		// Ansible hashi_vault lookups
		{
			Name:  "ansible_hashi_vault",
			Type:  "ansible_lookup",
			Regex: regexp.MustCompile(`lookup\s*\(\s*['"]hashi_vault['"],\s*['"]([^'"]+)['"]`),
		},
		{
			Name:  "ansible_vault_kv2_get",
			Type:  "ansible_module",
			Regex: regexp.MustCompile(`vault_kv2_get:\s*path:\s*['"]?([^'"}\s]+)['"]?`),
		},
		{
			Name:  "ansible_vault_read",
			Type:  "ansible_module",
			Regex: regexp.MustCompile(`vault_read:\s*path:\s*['"]?([^'"}\s]+)['"]?`),
		},

		// YAML configurations (generic secret/path references)
		{
			Name:  "yaml_vault_path",
			Type:  "yaml_config",
			Regex: regexp.MustCompile(`vault[_-]?path:\s*['"]?([^'"}\s]+)['"]?`),
		},
		{
			Name:  "yaml_secret_path",
			Type:  "yaml_config",
			Regex: regexp.MustCompile(`secret[_-]?path:\s*['"]?([^'"}\s]+)['"]?`),
		},

		// Terraform
		{
			Name:  "terraform_vault_generic_secret",
			Type:  "terraform",
			Regex: regexp.MustCompile(`data\s+"vault_generic_secret"\s+"\w+"\s+{\s+path\s+=\s+"([^"]+)"`),
		},
		{
			Name:  "terraform_vault_kv_secret_v2",
			Type:  "terraform",
			Regex: regexp.MustCompile(`data\s+"vault_kv_secret_v2"\s+"\w+"\s+{\s+mount\s+=\s+"([^"]+)"\s+name\s+=\s+"([^"]+)"`),
		},

		// Environment variables pointing to Vault paths
		{
			Name:  "env_var_vault",
			Type:  "env_var",
			Regex: regexp.MustCompile(`VAULT_PATH\s*=\s*['"]?([^'"}\s]+)['"]?`),
		},
		{
			Name:  "env_var_secret",
			Type:  "env_var",
			Regex: regexp.MustCompile(`SECRET_PATH\s*=\s*['"]?([^'"}\s]+)['"]?`),
		},

		// Python HVAC client
		{
			Name:  "python_hvac_read",
			Type:  "python_code",
			Regex: regexp.MustCompile(`client\.secrets\.kv\.v[12]\.read_secret(?:_version)?\s*\(\s*path\s*=\s*['"]([^'"]+)['"]`),
		},
		{
			Name:  "python_hvac_read_alt",
			Type:  "python_code",
			Regex: regexp.MustCompile(`client\.read\s*\(\s*['"]([^'"]+/data/[^'"]+)['"]`),
		},

		// Bash/Shell scripts
		{
			Name:  "bash_vault_read",
			Type:  "bash_script",
			Regex: regexp.MustCompile(`vault\s+(?:kv\s+)?read\s+['"]?([^'"\s]+)['"]?`),
		},
		{
			Name:  "bash_curl_vault",
			Type:  "bash_script",
			Regex: regexp.MustCompile(`curl.*\$VAULT_ADDR/v1/([^\s'"]+)`),
		},

		// Generic patterns (less specific, might have false positives)
		{
			Name:  "generic_secret_data",
			Type:  "generic",
			Regex: regexp.MustCompile(`['"]secret/data/([^'"]+)['"]`),
		},
		{
			Name:  "generic_kv_data",
			Type:  "generic",
			Regex: regexp.MustCompile(`['"]kv/data/([^'"]+)['"]`),
		},

		// Jinja2 templates
		{
			Name:  "jinja_vault_lookup",
			Type:  "jinja_template",
			Regex: regexp.MustCompile(`{{\s*lookup\s*\(\s*['"]vault['"],\s*['"]([^'"]+)['"]`),
		},

		// Docker/Kubernetes secrets (Vault injector annotations)
		{
			Name:  "k8s_vault_annotation",
			Type:  "k8s_annotation",
			Regex: regexp.MustCompile(`vault\.hashicorp\.com/agent-inject-secret-\w+:\s*['"]?([^'"}\s]+)['"]?`),
		},

		// Go code
		{
			Name:  "go_vault_read",
			Type:  "go_code",
			Regex: regexp.MustCompile(`client\.Logical\(\)\.Read\s*\(\s*"([^"]+)"`),
		},
	}
}
