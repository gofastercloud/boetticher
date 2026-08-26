package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPreferredAccessAliasUsesCanonicalNumberedDNSAlias(t *testing.T) {
	component := model.Component{Name: "lab-dns-01", DNSAliases: []string{"dns", "dns01"}}
	if got := preferredAccessAlias(component); got != "dns01" {
		t.Fatalf("preferredAccessAlias() = %q, want dns01", got)
	}
}
