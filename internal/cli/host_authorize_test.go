package cli

import (
	"encoding/json"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"testing"
)

func TestHostAuthorizeOptionsAndPublicRequest(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		action string
		ok     bool
	}{
		{[]string{"--home-recovery"}, "plan", true}, {[]string{"--home-recovery", "--plan"}, "plan", true}, {[]string{"--home-recovery", "--yes"}, "apply", true},
		{[]string{"--yes"}, "", false}, {[]string{"--home-recovery", "--plan", "--yes"}, "", false}, {[]string{"--home-recovery", "--unknown"}, "", false},
	} {
		o, err := parseHostAuthorizeOptions(tc.args)
		if (err == nil) != tc.ok {
			t.Fatalf("%v err=%v", tc.args, err)
		}
		if !tc.ok {
			continue
		}
		data, err := buildHostAuthorizeRequest(o, controllerhost.ControllerLABBinding{Address: "10.10.20.10", MAC: "6c:1f:f7:d2:5d:97"}, "ssh-ed25519 PUBLIC only-comment")
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]string
		if json.Unmarshal(data, &got) != nil || len(got) != 4 || got["action"] != tc.action || got["public_key"] != "ssh-ed25519 PUBLIC only-comment" {
			t.Fatalf("request=%s", data)
		}
	}
}
