package ansible

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestInventoryContainsBastionAndFixedAddresses(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := Inventory(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Inventory(site)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("inventory was not deterministic")
	}
	for _, expected := range []string{
		"lab-dns-01 ansible_host=10.10.20.10",
		"ProxyJump=lab-bastion",
		"HostKeyAlias=lab-dns-01.lab.home.arpa",
		"[managed:children]",
	} {
		if !strings.Contains(first, expected) {
			t.Errorf("inventory missing %q", expected)
		}
	}
}
