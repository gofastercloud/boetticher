package portal

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

type Evidence struct {
	GeneratedAt string        `json:"generated_at"`
	Results     []CheckResult `json:"results"`
}

type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func Build(s model.Site, outputDir, docsDir string, evidence Evidence, physical networkmodel.Discovery, now time.Time) error {
	if err := s.Validate(); err != nil {
		return err
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".boetticher-portal-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := writePage(filepath.Join(stage, "index.html"), page("boetticher", home(s, revision, evidence, now))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "inventory.html"), page("Inventory", inventory(s, revision))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "network.html"), page("Network", network(s, revision))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "services.html"), page("Services", services(s, revision))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "access.html"), page("Access", access(s, revision, physical))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "security.html"), page("Security", security(revision, evidence))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "pki.html"), page("PKI", pki(s, revision))); err != nil {
		return err
	}
	if err := writePage(filepath.Join(stage, "recovery.html"), page("Recovery", recovery(s, revision, evidence))); err != nil {
		return err
	}
	if err := copyDocs(stage, docsDir, revision); err != nil {
		return err
	}
	return publish(outputDir, stage)
}

func publish(outputDir, stage string) error {
	if info, err := os.Lstat(outputDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink portal output %s", outputDir)
		}
		previous := outputDir + ".previous"
		_ = os.RemoveAll(previous)
		if err := os.Rename(outputDir, previous); err != nil {
			return err
		}
		if err := os.Rename(stage, outputDir); err != nil {
			_ = os.Rename(previous, outputDir)
			return err
		}
		return os.RemoveAll(previous)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(stage, outputDir)
}

func page(title, body string) string {
	return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + html.EscapeString(title) + " · boetticher</title><style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}nav{display:flex;gap:1rem;flex-wrap:wrap}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd;padding:.5rem;text-align:left}code{background:#eef;padding:.1rem .3rem}pre{white-space:pre-wrap;background:#f5f7f9;padding:1rem}.pass{color:#087f23}.fail{color:#b00020}.notice{color:#8a5b00}</style></head><body><nav><a href=\"/index.html\">Home</a><a href=\"/inventory.html\">Inventory</a><a href=\"/network.html\">Network</a><a href=\"/services.html\">Services</a><a href=\"/access.html\">Access</a><a href=\"/pki.html\">PKI</a><a href=\"/security.html\">Security</a><a href=\"/recovery.html\">Recovery</a><a href=\"/docs/index.html\">Runbooks</a></nav><main><h1>" + html.EscapeString(title) + "</h1>" + body + "</main></body></html>\n"
}

func home(s model.Site, revision string, evidence Evidence, now time.Time) string {
	status := "NOT TESTED"
	if len(evidence.Results) > 0 {
		status = "PARTIAL"
		for _, result := range evidence.Results {
			if result.Status == "FAIL" {
				status = "FAIL"
				break
			}
		}
	}
	return fmt.Sprintf("<p>Generated platform view; not a wiki or monitoring dashboard.</p><table><tr><th>Platform version</th><td>%s</td></tr><tr><th>Schema</th><td>%d</td></tr><tr><th>Model revision</th><td><code>%s</code></td></tr><tr><th>Portal generated</th><td>%s</td></tr><tr><th>Latest verification</th><td>%s</td></tr></table><h2>Quick links</h2><p><a href=\"%s\">Proxmox</a> · <a href=\"https://opnsense.%s\">OPNsense</a> · <a href=\"https://monitor.%s\">Zabbix</a> · <a href=\"https://dns.%s\">DNS</a></p>", html.EscapeString(s.PlatformVersion), s.SchemaVersion, html.EscapeString(revision), now.UTC().Format(time.RFC3339), html.EscapeString(status), html.EscapeString("https://proxmox."+s.Network.Domain+":8006"), html.EscapeString(s.Network.Domain), html.EscapeString(s.Network.Domain), html.EscapeString(s.Network.Domain))
}

func inventory(s model.Site, revision string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Model revision: <code>%s</code></p><p>Platform guests are managed by boetticher. Any user-managed entries shown here are informational only.</p><table><tr><th>Host</th><th>Ownership</th><th>Zone</th><th>Address</th><th>Role</th><th>Monitoring</th><th>Backup</th></tr>", html.EscapeString(revision))
	for _, m := range sortedComponents(s) {
		ownership := "user-managed / informational"
		if m.ProductOwned {
			ownership = "boetticher platform"
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(m.Hostname), html.EscapeString(ownership), html.EscapeString(m.Zone), html.EscapeString(m.Address), html.EscapeString(m.Role), checkMark(m.Monitoring), checkMark(m.Backup))
	}
	b.WriteString("</table>")
	return b.String()
}

func network(s model.Site, revision string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Model revision: <code>%s</code></p><pre>HOME / upstream\n  |\nProxmox → OPNsense\n  |\nvmbr1 (VLAN-aware internal bridge)\n  +-- TRUSTED VLAN 10\n  +-- SERVERS VLAN 20\n  +-- SANDBOX VLAN 50\n  `-- MGMT VLAN 99</pre><table><tr><th>Zone</th><th>VLAN</th><th>Network</th><th>Gateway</th><th>DHCP mode</th></tr>", html.EscapeString(revision))
	for _, z := range s.Network.Zones {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(z.Name), z.VLAN, html.EscapeString(z.Network), html.EscapeString(z.Gateway), html.EscapeString(z.AddressMode))
	}
	b.WriteString("</table>")
	return b.String()
}

func services(s model.Site, revision string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Model revision: <code>%s</code></p><table><tr><th>Service</th><th>URL</th><th>SSH</th><th>mTLS</th></tr>", html.EscapeString(revision))
	for _, m := range sortedComponents(s) {
		if !m.ProductOwned || (m.URL == "" && !m.SSHManaged) {
			continue
		}
		url := m.URL
		if url == "" {
			url = "—"
		}
		ssh := "—"
		if m.SSHManaged {
			ssh = "managed via lab-bastion"
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(m.Role), html.EscapeString(url), html.EscapeString(ssh), checkMark(m.MTLS))
	}
	b.WriteString("</table>")
	return b.String()
}

func access(s model.Site, revision string, physical networkmodel.Discovery) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Model revision: <code>%s</code></p><p>Internal SSH uses fixed IPs and the Proxmox forwarding-only bastion. Internal DNS is not required for the SSH journey.</p>", html.EscapeString(revision))
	if s.BootstrapAddress == "" {
		b.WriteString("<p class=\"notice\">Bootstrap endpoint: not configured.</p>")
	} else {
		fmt.Fprintf(&b, "<p>Bootstrap endpoint: <code>%s</code> · <code>ssh proxmox</code> · <code>ssh lab-bastion</code></p>", html.EscapeString(s.BootstrapAddress))
	}
	b.WriteString("<table><tr><th>Canonical host</th><th>Aliases</th><th>Fixed address</th><th>User</th><th>Path</th></tr>")
	for _, m := range sortedComponents(s) {
		if !m.ProductOwned || !m.SSHManaged {
			continue
		}
		aliases := append([]string{m.Name, m.Hostname + "." + s.Network.Domain}, m.DNSAliases...)
		user := m.SSHUser
		if user == "" {
			user = model.DefaultAdminSSHUser
		}
		path := "direct"
		if m.JumpAllowed {
			path = "ProxyJump lab-bastion"
		}
		fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(m.Hostname+"."+s.Network.Domain), html.EscapeString(strings.Join(unique(aliases), ", ")), html.EscapeString(m.Address), html.EscapeString(user), html.EscapeString(path))
	}
	b.WriteString("</table>")
	physicalMode := s.PhysicalNetwork.Mode
	if physical.Status != "MODEL" && physical.Mode != "" {
		physicalMode = physical.Mode
	}
	if physicalMode == "virtual-only" {
		b.WriteString("<p class=\"notice\">Physical network: virtual-only bootstrap mode; no vmbr1 physical member is recorded.</p>")
	} else if physicalMode == "selection-required" {
		b.WriteString("<p class=\"notice\">Physical network: multiple eligible trunk interfaces require explicit operator selection.</p>")
	} else {
		trunkName := s.PhysicalNetwork.Trunk.Name
		if physical.Trunk != nil {
			trunkName = physical.Trunk.Name
		}
		fmt.Fprintf(&b, "<p>Physical network: <code>%s</code> attached to vmbr1.</p>", html.EscapeString(trunkName))
	}
	fmt.Fprintf(&b, "<h2>Physical network evidence</h2><p>Upstream address: <code>%s</code></p><table><tr><th>Role</th><th>Interface</th><th>Permanent MAC</th><th>PCI</th><th>Driver</th><th>Model</th><th>Speed</th><th>Carrier</th><th>Bridge</th><th>Addresses</th></tr>", html.EscapeString(physical.BootstrapAddress))
	writePhysicalRow(&b, "upstream/bootstrap", physical.Upstream)
	if physical.Trunk != nil {
		writePhysicalRow(&b, "internal trunk", *physical.Trunk)
	} else {
		b.WriteString("<tr><td>internal trunk</td><td colspan=\"9\">virtual-only / no physical member</td></tr>")
	}
	b.WriteString("</table>")
	return b.String()
}

func writePhysicalRow(b *strings.Builder, role string, iface networkmodel.Interface) {
	speed := "unknown"
	if iface.SpeedMbps > 0 {
		speed = fmt.Sprintf("%d Mb/s", iface.SpeedMbps)
	}
	fmt.Fprintf(b, "<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%t</td><td>%s</td><td>%s</td></tr>", html.EscapeString(role), html.EscapeString(iface.Name), html.EscapeString(iface.PermanentMAC), html.EscapeString(iface.PCIAddress), html.EscapeString(iface.Driver), html.EscapeString(iface.Model), html.EscapeString(speed), iface.Carrier, html.EscapeString(iface.Bridge), html.EscapeString(strings.Join(iface.Addresses, ", ")))
}

func unique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func security(revision string, evidence Evidence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Model revision: <code>%s</code></p><p>Expected security properties and latest available conformance evidence. Live telemetry belongs to Zabbix.</p><table><tr><th>Property</th><th>Status</th><th>Detail</th></tr>", html.EscapeString(revision))
	for _, result := range evidence.Results {
		class := strings.ToLower(result.Status)
		fmt.Fprintf(&b, "<tr><td>%s</td><td class=\"%s\">%s</td><td>%s</td></tr>", html.EscapeString(result.Name), html.EscapeString(class), html.EscapeString(result.Status), html.EscapeString(result.Detail))
	}
	if len(evidence.Results) == 0 {
		b.WriteString("<tr><td colspan=\"3\">NOT TESTED — no verification evidence has been generated.</td></tr>")
	}
	b.WriteString("</table>")
	return b.String()
}

func pki(s model.Site, revision string) string {
	return fmt.Sprintf("<p>Model revision: <code>%s</code></p><table><tr><th>Authority</th><th>Common name</th><th>Fingerprint</th><th>Expiry</th></tr><tr><td>Root CA</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr><tr><td>Issuing CA</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr></table><p>Endpoint private keys and CA private keys are not rendered here.</p>", html.EscapeString(revision), html.EscapeString(s.PKI.RootCommonName), html.EscapeString(s.PKI.RootFingerprint), html.EscapeString(s.PKI.RootExpiry), html.EscapeString(s.PKI.IssuingCommonName), html.EscapeString(s.PKI.IssuingFingerprint), html.EscapeString(s.PKI.IssuingExpiry))
}

func recovery(s model.Site, revision string, evidence Evidence) string {
	return fmt.Sprintf("<p>Model revision: <code>%s</code></p><h2>Preserve</h2><ul><li>Private site repository containing desired state and encrypted secrets.</li><li>Independent recovery copy of the Age private identity.</li></ul><h2>Profiles</h2><p>Storage profile: <code>%s</code>. Same-disk backups are not disaster recovery.</p><p>Platform backup job: <code>boetticher-platform</code> for VM/LXC IDs 100, 110, 111, 120, and 130. User workloads remain outside the platform guarantee.</p><p>Age recovery and backup freshness are reported only when current evidence exists.</p>", html.EscapeString(revision), html.EscapeString(s.StorageProfile))
}

func copyDocs(outputDir, docsDir, revision string) error {
	destination := filepath.Join(outputDir, "docs")
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	entries := []string{}
	if docsDir != "" {
		_ = filepath.Walk(docsDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".md") {
				entries = append(entries, path)
			}
			return nil
		})
	}
	sort.Strings(entries)
	var index strings.Builder
	fmt.Fprintf(&index, "<p>Model revision: <code>%s</code></p><ul>", html.EscapeString(revision))
	for _, source := range entries {
		rel, err := filepath.Rel(docsDir, source)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), ".md") + ".html"
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		pagePath := filepath.Join(destination, filepath.FromSlash(name))
		if err := writePage(pagePath, page(filepath.ToSlash(rel), "<pre>"+html.EscapeString(string(data))+"</pre>")); err != nil {
			return err
		}
		fmt.Fprintf(&index, "<li><a href=\"%s\">%s</a></li>", html.EscapeString(filepath.ToSlash(name)), html.EscapeString(filepath.ToSlash(rel)))
	}
	index.WriteString("</ul>")
	return writePage(filepath.Join(destination, "index.html"), page("Runbooks", index.String()))
}

func sortedComponents(s model.Site) []model.Component {
	copyComponents := append([]model.Component(nil), s.Components...)
	sort.Slice(copyComponents, func(i, j int) bool { return copyComponents[i].Name < copyComponents[j].Name })
	return copyComponents
}

func checkMark(value bool) string {
	if value {
		return "✓"
	}
	return "—"
}

func writePage(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".boetticher-portal-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
