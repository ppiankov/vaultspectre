package eso

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseDirectory walks dir recursively and returns all ExternalSecret CRDs found.
// Non-YAML files and YAML documents that are not ExternalSecrets are silently skipped.
func ParseDirectory(dir string) ([]*ExternalSecret, error) {
	var results []*ExternalSecret

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		parsed, parseErr := parseFile(path)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		results = append(results, parsed...)
		return nil
	})

	return results, err
}

func parseFile(path string) ([]*ExternalSecret, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseReader(f, path)
}

func parseReader(r io.Reader, sourcePath string) ([]*ExternalSecret, error) {
	dec := yaml.NewDecoder(r)
	var results []*ExternalSecret

	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode {
			continue
		}

		apiVersionNode := mappingGet(root, "apiVersion")
		kindNode := mappingGet(root, "kind")
		if apiVersionNode == nil || kindNode == nil {
			continue
		}
		if !strings.HasPrefix(apiVersionNode.Value, "external-secrets.io/") {
			continue
		}
		if kindNode.Value != "ExternalSecret" {
			continue
		}

		es, err := nodeToExternalSecret(root, sourcePath)
		if err != nil {
			return nil, fmt.Errorf("parse ExternalSecret in %s: %w", sourcePath, err)
		}
		results = append(results, es)
	}

	return results, nil
}

func nodeToExternalSecret(root *yaml.Node, sourcePath string) (*ExternalSecret, error) {
	es := &ExternalSecret{SourceFile: sourcePath}

	meta := mappingGet(root, "metadata")
	if meta != nil {
		es.Name = nodeString(mappingGet(meta, "name"))
		es.Namespace = nodeString(mappingGet(meta, "namespace"))
	}

	spec := mappingGet(root, "spec")
	if spec == nil {
		return es, nil
	}

	es.RefreshInterval = nodeString(mappingGet(spec, "refreshInterval"))

	provider := mappingGet(spec, "provider")
	if provider != nil {
		if vaultProv := mappingGet(provider, "vault"); vaultProv != nil {
			es.VaultMount = nodeString(mappingGet(vaultProv, "path"))
		}
	}

	ssRef := mappingGet(spec, "secretStoreRef")
	if ssRef != nil {
		es.SecretStoreRef = SecretStoreRef{
			Name: nodeString(mappingGet(ssRef, "name")),
			Kind: nodeString(mappingGet(ssRef, "kind")),
		}
	}

	target := mappingGet(spec, "target")
	if target != nil {
		es.TargetName = nodeString(mappingGet(target, "name"))
	}
	if es.TargetName == "" {
		es.TargetNameMissing = true
	}

	dataNode := mappingGet(spec, "data")
	if dataNode != nil && dataNode.Kind == yaml.SequenceNode {
		for _, item := range dataNode.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			entry := DataEntry{SourceLine: item.Line}
			entry.SecretKey = nodeString(mappingGet(item, "secretKey"))
			remoteRef := mappingGet(item, "remoteRef")
			if remoteRef != nil {
				entry.RemoteRefKey = nodeString(mappingGet(remoteRef, "key"))
				entry.RemoteRefProperty = nodeString(mappingGet(remoteRef, "property"))
			}
			es.Data = append(es.Data, entry)
		}
	}

	dataFromNode := mappingGet(spec, "dataFrom")
	if dataFromNode != nil && dataFromNode.Kind == yaml.SequenceNode {
		for _, item := range dataFromNode.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			entry := DataFromEntry{PullAll: true, SourceLine: item.Line}
			// ESO v1beta1: dataFrom[].extract.key
			extract := mappingGet(item, "extract")
			if extract != nil {
				entry.RemoteRefKey = nodeString(mappingGet(extract, "key"))
			} else {
				// Legacy v1alpha1: dataFrom[].key
				entry.RemoteRefKey = nodeString(mappingGet(item, "key"))
			}
			// Skip find/rewrite entries (no key to extract)
			if entry.RemoteRefKey == "" {
				continue
			}
			es.DataFrom = append(es.DataFrom, entry)
		}
	}

	return es, nil
}

// mappingGet returns the value node for key in a YAML mapping node, or nil if not found.
func mappingGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// nodeString returns the string value of a scalar node, or "" if nil or not scalar.
func nodeString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
