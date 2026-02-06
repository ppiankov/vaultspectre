package scanner

import (
	"fmt"
	"strings"
)

// Resolver resolves variables in Vault paths
type Resolver struct {
	variables map[string]string
}

// NewResolver creates a new resolver with provided variables
func NewResolver(variables map[string]string) *Resolver {
	return &Resolver{
		variables: variables,
	}
}

// Resolve resolves variables in a reference
// Returns resolved reference and any missing variables
func (r *Resolver) Resolve(ref Reference) (Reference, []string, error) {
	// If no variables, already resolved
	if len(ref.Variables) == 0 {
		if ref.ResolvedPath == "" {
			ref.ResolvedPath = ref.Path
		}
		return ref, nil, nil
	}

	// Try to resolve each variable
	resolved := ref.Path
	missingVars := []string{}
	resolvedVars := make(map[string]string)

	for _, varName := range ref.Variables {
		value, exists := r.variables[varName]
		if !exists {
			missingVars = append(missingVars, varName)
			continue
		}

		// Replace {{ varName }} with value
		placeholder := "{{ " + varName + " }}"
		resolved = strings.ReplaceAll(resolved, placeholder, value)
		resolvedVars[varName] = value
	}

	if len(missingVars) > 0 {
		// ROOTOPS: Cannot resolve without all variables
		ref.Status = "unresolved"
		ref.ErrorMsg = fmt.Sprintf("missing variables: %v", missingVars)
		return ref, missingVars, fmt.Errorf("cannot resolve path - missing variables: %v", missingVars)
	}

	// Successfully resolved
	ref.ResolvedPath = resolved
	ref.Status = "pending_validation"
	return ref, nil, nil
}

// ResolveAll resolves variables in all references
func (r *Resolver) ResolveAll(refs []Reference) ([]Reference, map[string][]string) {
	resolved := make([]Reference, 0, len(refs))
	unresolved := make(map[string][]string) // missing var -> paths that need it

	for _, ref := range refs {
		resolvedRef, missingVars, _ := r.Resolve(ref)
		resolved = append(resolved, resolvedRef)

		// Track which paths need which variables
		for _, varName := range missingVars {
			unresolved[varName] = append(unresolved[varName], ref.Path)
		}
	}

	return resolved, unresolved
}

// DetectVariables analyzes references and returns all unique variables found
func (r *Resolver) DetectVariables(refs []Reference) []string {
	varSet := make(map[string]bool)
	for _, ref := range refs {
		for _, varName := range ref.Variables {
			varSet[varName] = true
		}
	}

	vars := make([]string, 0, len(varSet))
	for varName := range varSet {
		vars = append(vars, varName)
	}
	return vars
}

// DetectVariables is a package-level convenience function
func DetectVariables(refs []Reference) []string {
	varSet := make(map[string]bool)
	for _, ref := range refs {
		for _, varName := range ref.Variables {
			varSet[varName] = true
		}
	}

	vars := make([]string, 0, len(varSet))
	for varName := range varSet {
		vars = append(vars, varName)
	}
	return vars
}
