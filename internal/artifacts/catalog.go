package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/gofastercloud/boetticher/internal/model"
)

// Definition describes the checked-in build contract for an official
// appliance. The resulting artifact is still built and qualified outside the
// ordinary offline test path; the digest is deterministic until that artifact
// is published.
type Definition struct {
	Name         string
	Version      string
	Kind         string
	Architecture string
	Base         string
	BaseVersion  string
}

const (
	BaseName      = "boetticher-base"
	BaseVersion   = "0.3.0"
	Architecture  = "amd64"
	DebianRelease = "13"
	ModuleVersion = "1.0.0"
)

func Definitions() []Definition {
	return []Definition{
		{Name: "dns", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "monitoring", Version: ModuleVersion, Kind: "lxc", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
		{Name: "firewall", Version: ModuleVersion, Kind: "qemu", Architecture: Architecture, Base: BaseName, BaseVersion: BaseVersion},
	}
}

func Lookup(module string) (Definition, bool) {
	for _, definition := range Definitions() {
		if definition.Name == module {
			return definition, true
		}
	}
	return Definition{}, false
}

func ArtifactFor(module string) (model.Artifact, error) {
	definition, ok := Lookup(module)
	if !ok {
		return model.Artifact{}, fmt.Errorf("no built-in artifact definition for module %q", module)
	}
	identity := fmt.Sprintf("%s/%s/%s/%s/%s/%s", definition.Base, definition.BaseVersion, definition.Name, definition.Version, definition.Architecture, definition.Kind)
	definitionDigest := digest(identity)
	artifactDigest := digest("artifact/" + identity + "/" + definitionDigest)
	return model.Artifact{
		Name:             "boetticher-" + module,
		Version:          definition.Version,
		Architecture:     definition.Architecture,
		Kind:             definition.Kind,
		SHA256:           artifactDigest,
		DefinitionSHA256: definitionDigest,
	}, nil
}

func ValidateDefinitions() error {
	for _, definition := range Definitions() {
		if definition.Base != BaseName || definition.BaseVersion != BaseVersion {
			return fmt.Errorf("artifact %s does not consume the pinned %s base", definition.Name, BaseName)
		}
		if definition.Architecture != Architecture || definition.Version == "" || definition.Kind == "" {
			return fmt.Errorf("artifact %s has incomplete identity", definition.Name)
		}
	}
	return nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
