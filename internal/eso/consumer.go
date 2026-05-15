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

// ConsumedKey is a Secret key reference found in a workload manifest or Helm values file.
type ConsumedKey struct {
	SecretName   string
	Key          string // empty when PullAll=true
	PullAll      bool   // true for envFrom.secretRef and volume mounts
	ConsumerKind string // "env", "envFrom", "volume", "initContainer.env", "initContainer.envFrom", "sidecar.env", "sidecar.envFrom"
	SourceFile   string
	SourceLine   int
}

// ReloaderReference is a Secret name extracted from a Stakater Reloader annotation.
type ReloaderReference struct {
	SecretName string
	SourceFile string
	SourceLine int
}

// ConsumerScanResult holds all consumer-side references found by ScanConsumers.
type ConsumerScanResult struct {
	Consumers          []ConsumedKey
	ReloaderReferences []ReloaderReference
}

var workloadKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
	"CronJob":     true,
}

// ScanConsumers scans each path (file or directory) for Secret consumption patterns.
// Recognises K8s workload manifests and Helm values files with a top-level env: list.
func ScanConsumers(paths []string) (*ConsumerScanResult, error) {
	result := &ConsumerScanResult{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if info.IsDir() {
			if err := scanConsumerDir(p, result); err != nil {
				return nil, err
			}
		} else {
			if err := scanConsumerFile(p, result); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func scanConsumerDir(dir string, result *ConsumerScanResult) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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
		return scanConsumerFile(path, result)
	})
}

func scanConsumerFile(path string, result *ConsumerScanResult) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return scanConsumerReader(f, path, result)
}

func scanConsumerReader(r io.Reader, sourcePath string, result *ConsumerScanResult) error {
	dec := yaml.NewDecoder(r)
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode {
			continue
		}

		kindNode := mappingGet(root, "kind")
		if kindNode != nil && workloadKinds[kindNode.Value] {
			extractFromWorkload(root, sourcePath, result)
			continue
		}

		// Helm values: no kind/apiVersion, has a top-level env sequence
		apiVersionNode := mappingGet(root, "apiVersion")
		if (kindNode == nil || kindNode.Value == "") && (apiVersionNode == nil || apiVersionNode.Value == "") {
			envNode := mappingGet(root, "env")
			if envNode != nil && envNode.Kind == yaml.SequenceNode {
				extractFromEnvList(envNode, "env", sourcePath, result)
			}
		}
	}
	return nil
}

func extractFromWorkload(root *yaml.Node, sourcePath string, result *ConsumerScanResult) {
	kindNode := mappingGet(root, "kind")
	spec := mappingGet(root, "spec")
	if spec == nil {
		return
	}

	var podSpec *yaml.Node
	var templateMeta *yaml.Node

	if kindNode != nil && kindNode.Value == "CronJob" {
		jobTemplate := mappingGet(spec, "jobTemplate")
		if jobTemplate == nil {
			return
		}
		jobSpec := mappingGet(jobTemplate, "spec")
		if jobSpec == nil {
			return
		}
		template := mappingGet(jobSpec, "template")
		if template != nil {
			podSpec = mappingGet(template, "spec")
			templateMeta = mappingGet(template, "metadata")
		}
	} else {
		template := mappingGet(spec, "template")
		if template != nil {
			podSpec = mappingGet(template, "spec")
			templateMeta = mappingGet(template, "metadata")
		}
	}

	if templateMeta != nil {
		annotations := mappingGet(templateMeta, "annotations")
		if annotations != nil {
			extractReloaderAnnotations(annotations, sourcePath, result)
		}
	}

	if podSpec == nil {
		return
	}

	// Volumes
	volumesNode := mappingGet(podSpec, "volumes")
	if volumesNode != nil && volumesNode.Kind == yaml.SequenceNode {
		for _, vol := range volumesNode.Content {
			secretNode := mappingGet(vol, "secret")
			if secretNode == nil {
				continue
			}
			name := nodeString(mappingGet(secretNode, "secretName"))
			if name == "" || isTemplateVar(name) {
				continue
			}
			result.Consumers = append(result.Consumers, ConsumedKey{
				SecretName:   name,
				PullAll:      true,
				ConsumerKind: "volume",
				SourceFile:   sourcePath,
				SourceLine:   vol.Line,
			})
		}
	}

	// initContainers
	initContainersNode := mappingGet(podSpec, "initContainers")
	if initContainersNode != nil && initContainersNode.Kind == yaml.SequenceNode {
		for _, container := range initContainersNode.Content {
			envNode := mappingGet(container, "env")
			if envNode != nil {
				extractFromEnvList(envNode, "initContainer.env", sourcePath, result)
			}
			envFromNode := mappingGet(container, "envFrom")
			if envFromNode != nil {
				extractFromEnvFrom(envFromNode, "initContainer.envFrom", sourcePath, result)
			}
		}
	}

	// containers (index 0 = main, index > 0 = sidecar)
	containersNode := mappingGet(podSpec, "containers")
	if containersNode == nil || containersNode.Kind != yaml.SequenceNode {
		return
	}
	for i, container := range containersNode.Content {
		envKind := "env"
		envFromKind := "envFrom"
		if i > 0 {
			envKind = "sidecar.env"
			envFromKind = "sidecar.envFrom"
		}
		envNode := mappingGet(container, "env")
		if envNode != nil {
			extractFromEnvList(envNode, envKind, sourcePath, result)
		}
		envFromNode := mappingGet(container, "envFrom")
		if envFromNode != nil {
			extractFromEnvFrom(envFromNode, envFromKind, sourcePath, result)
		}
	}
}

func extractFromEnvList(envNode *yaml.Node, consumerKind, sourcePath string, result *ConsumerScanResult) {
	if envNode == nil || envNode.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range envNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		valueFrom := mappingGet(item, "valueFrom")
		if valueFrom == nil {
			continue
		}
		secretKeyRef := mappingGet(valueFrom, "secretKeyRef")
		if secretKeyRef == nil {
			continue
		}
		name := nodeString(mappingGet(secretKeyRef, "name"))
		key := nodeString(mappingGet(secretKeyRef, "key"))
		if name == "" || isTemplateVar(name) {
			continue
		}
		result.Consumers = append(result.Consumers, ConsumedKey{
			SecretName:   name,
			Key:          key,
			ConsumerKind: consumerKind,
			SourceFile:   sourcePath,
			SourceLine:   item.Line,
		})
	}
}

func extractFromEnvFrom(envFromNode *yaml.Node, consumerKind, sourcePath string, result *ConsumerScanResult) {
	if envFromNode == nil || envFromNode.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range envFromNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		secretRef := mappingGet(item, "secretRef")
		if secretRef == nil {
			continue
		}
		name := nodeString(mappingGet(secretRef, "name"))
		if name == "" || isTemplateVar(name) {
			continue
		}
		result.Consumers = append(result.Consumers, ConsumedKey{
			SecretName:   name,
			PullAll:      true,
			ConsumerKind: consumerKind,
			SourceFile:   sourcePath,
			SourceLine:   item.Line,
		})
	}
}

func extractReloaderAnnotations(annotations *yaml.Node, sourcePath string, result *ConsumerScanResult) {
	reloadNode := mappingGet(annotations, "secret.reloader.stakater.com/reload")
	if reloadNode == nil || reloadNode.Value == "" {
		return
	}
	for _, name := range strings.Split(reloadNode.Value, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			result.ReloaderReferences = append(result.ReloaderReferences, ReloaderReference{
				SecretName: name,
				SourceFile: sourcePath,
				SourceLine: reloadNode.Line,
			})
		}
	}
}

// isTemplateVar returns true if s contains Helm/Go template syntax ({{ }}).
func isTemplateVar(s string) bool {
	return strings.Contains(s, "{{")
}
