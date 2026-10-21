package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rootedTransport runs the remote command locally with the fixed Host paths
// rewritten under a temporary root.
func rootedTransport(t *testing.T, root string) Transport {
	t.Helper()
	transport := streamingTransport(t)
	script := "#!/bin/sh\nfor last; do :; done\nlast=$(printf %s \"$last\" | sed -e 's#/etc/#" + root + "/etc/#g' -e 's#/usr/local/#" + root + "/usr/local/#g')\nexec /bin/sh -c \"$last\"\n"
	if err := os.WriteFile(transport.SSHPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return transport
}

func writeRooted(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineOwnedPresentIgnoresHelperVersion(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  bool
	}{
		"nothing":                 {files: nil, want: false},
		"stale v1 helper only":    {files: map[string]string{"/usr/local/libexec/boetticher-host-speedtest": "#!/bin/sh\nexit 2\n"}, want: true},
		"owned repository":        {files: map[string]string{proxmoxRepositoryPath: proxmoxRepository}, want: true},
		"owned headless policy":   {files: map[string]string{headlessPolicyPath: headlessPolicy}, want: true},
		"foreign repository only": {files: map[string]string{proxmoxRepositoryPath: "Types: deb\nURIs: http://example.invalid\n"}, want: false},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range item.files {
				writeRooted(t, root, path, content)
			}
			owned, err := BaselineOwnedPresent(context.Background(), rootedTransport(t, root))
			if err != nil || owned != item.want {
				t.Fatalf("owned=%t err=%v, want %t", owned, err, item.want)
			}
		})
	}
}

func TestBaselineOwnedPresentReportsInspectionFailure(t *testing.T) {
	transport := streamingTransport(t)
	if err := os.WriteFile(transport.SSHPath, []byte("#!/bin/sh\necho denied >&2\nexit 255\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := BaselineOwnedPresent(context.Background(), transport); err == nil || !strings.Contains(err.Error(), "inspect owned Host baseline") {
		t.Fatalf("transport failure was treated as absent: %v", err)
	}
	if _, err := parseOwnedBaseline("garbage"); err == nil {
		t.Fatal("unexpected response accepted")
	}
}
