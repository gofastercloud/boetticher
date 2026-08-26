package model

import (
	"strings"
	"testing"
)

func TestParseSiteConfigRequiresV3API(t *testing.T) {
	_, err := ParseSiteConfig([]byte("modules: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "api_version is required") {
		t.Fatalf("missing v3 api version was accepted: %v", err)
	}
}
