package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestCheckPlatformOwnershipIncludesComposedLoggingGuest(t *testing.T) {
	managed := model.NewDefaultSite("verify", "age1verify")
	if err := checkPlatformOwnership(managed); err != nil {
		t.Fatalf("managed composed platform was rejected: %v", err)
	}

	external := model.NewSite("verify-external", "age1verify", model.GatewayModeExternal)
	if err := checkPlatformOwnership(external); err != nil {
		t.Fatalf("external composed platform was rejected: %v", err)
	}
}
