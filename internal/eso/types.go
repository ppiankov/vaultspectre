package eso

// ExternalSecret is a parsed ExternalSecret CRD from a YAML manifest.
type ExternalSecret struct {
	Name              string
	Namespace         string
	VaultMount        string // spec.provider.vault.path — the KV mount (e.g. "kv")
	TargetName        string
	TargetNameMissing bool // true when spec.target.name is absent; ESO defaults to metadata.name
	RefreshInterval   string
	SecretStoreRef    SecretStoreRef
	Data              []DataEntry
	DataFrom          []DataFromEntry
	SourceFile        string
}

// SecretStoreRef identifies the ESO SecretStore or ClusterSecretStore backing this resource.
type SecretStoreRef struct {
	Name string
	Kind string
}

// DataEntry corresponds to one spec.data[] item.
type DataEntry struct {
	SecretKey         string
	RemoteRefKey      string // Vault path
	RemoteRefProperty string // Vault property key; empty means whole-key semantics
	SourceLine        int
}

// DataFromEntry corresponds to one spec.dataFrom[] item (whole-path pull).
type DataFromEntry struct {
	RemoteRefKey string
	PullAll      bool // always true — dataFrom pulls all properties at the path
	SourceLine   int
}
