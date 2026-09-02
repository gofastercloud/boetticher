package gatus

import (
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"strings"
	"testing"
)

func TestRenderConfigurationIsManagedOnlyDeterministicAndEphemeral(t *testing.T) {
	c := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	on := true
	c.Modules.Gatus = &model.NetworkToggleModuleConfig{Enabled: &on}
	s, _, err := modules.Compose(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := RenderConfiguration(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderConfiguration(s)
	if err != nil {
		t.Fatal(err)
	}
	text := string(a)
	if text != string(b) || !strings.Contains(text, "type: memory") || !strings.Contains(text, "https://monitor.lab.home.arpa") || strings.Contains(text, "https://gatus.lab.home.arpa") || strings.Contains(text, "user-vm") {
		t.Fatalf("unexpected Gatus config: %s", text)
	}
}
