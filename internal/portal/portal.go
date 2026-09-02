package portal

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

type Evidence struct {
	GeneratedAt string              `json:"generated_at"`
	Results     []CheckResult       `json:"results"`
	Status      *statusmodel.Report `json:"-"`
}

type CheckResult struct {
	Name       string                   `json:"name"`
	Status     string                   `json:"status"`
	Detail     string                   `json:"detail,omitempty"`
	Tier       statusmodel.EvidenceTier `json:"evidence_tier,omitempty"`
	ObservedAt string                   `json:"observed_at,omitempty"`
	Reason     string                   `json:"reason,omitempty"`
	NextAction string                   `json:"next_action,omitempty"`
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
	if err := pathguard.ValidateNoSymlinkComponents(outputDir); err != nil {
		return fmt.Errorf("refuse portal output path: %w", err)
	}
	if err := pathguard.MkdirAll(parent, 0755); err != nil {
		return err
	}
	stage, err := pathguard.MkdirTemp(parent, ".boetticher-portal-stage-", 0700)
	if err != nil {
		return err
	}
	defer pathguard.RemoveAll(stage)
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
	if err := writePage(filepath.Join(stage, "security.html"), page("Lab checks", security(revision, evidence))); err != nil {
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
	if err := pathguard.ValidateNoSymlinkComponents(outputDir); err != nil {
		return fmt.Errorf("refuse portal publication path: %w", err)
	}
	previous := outputDir + ".previous"
	if err := pathguard.ValidateNoSymlinkComponents(previous); err != nil {
		return fmt.Errorf("refuse portal previous path: %w", err)
	}
	if _, err := os.Lstat(outputDir); err == nil {
		if err := pathguard.RemoveAll(previous); err != nil {
			return err
		}
		if err := pathguard.Rename(outputDir, previous); err != nil {
			return err
		}
		if err := pathguard.Rename(stage, outputDir); err != nil {
			_ = pathguard.Rename(previous, outputDir)
			return err
		}
		return pathguard.RemoveAll(previous)
	} else if !os.IsNotExist(err) {
		return err
	}
	return pathguard.Rename(stage, outputDir)
}

func page(title, body string) string {
	return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + html.EscapeString(title) + " · boetticher</title><style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}nav{display:flex;gap:1rem;flex-wrap:wrap}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd;padding:.5rem;text-align:left}code{background:#eef;padding:.1rem .3rem}pre{white-space:pre-wrap;background:#f5f7f9;padding:1rem}.pass{color:#087f23}.fail{color:#b00020}.notice{color:#8a5b00}</style></head><body><nav><a href=\"/index.html\">Home</a><a href=\"/inventory.html\">Inventory</a><a href=\"/network.html\">Network</a><a href=\"/services.html\">Services</a><a href=\"/access.html\">Access</a><a href=\"/pki.html\">Certificates</a><a href=\"/security.html\">Checks</a><a href=\"/recovery.html\">Recovery</a><a href=\"/docs/index.html\">Guides</a></nav><main><h1>" + html.EscapeString(title) + "</h1>" + body + "</main></body></html>\n"
}

func home(s model.Site, revision string, evidence Evidence, _ time.Time) string {
	checks := make([]statusmodel.LegacyCheck, 0, len(evidence.Results))
	for _, result := range evidence.Results {
		checks = append(checks, statusmodel.LegacyCheck{
			Name: result.Name, Status: result.Status, Detail: result.Detail,
			Tier: result.Tier, ObservedAt: result.ObservedAt,
			Reason: result.Reason, NextAction: result.NextAction,
		})
	}
	semantic := statusmodel.FromLegacy(revision, evidence.GeneratedAt, checks)
	if evidence.Status != nil && evidence.Status.StatusModelVersion == statusmodel.ModelVersion && evidence.Status.ModelRevision == revision {
		semantic = *evidence.Status
	}
	gateway := "external firewall"
	if s.Gateway.Mode == model.GatewayModeManaged {
		gateway = "managed Debian firewall"
	}
	var moduleTable strings.Builder
	moduleTable.WriteString("<h2>Enabled modules</h2><table><tr><th>Name</th><th>Starts as</th><th>State</th><th>Note</th></tr>")
	for _, module := range s.Modules {
		if !module.Enabled {
			continue
		}
		state := module.State
		fmt.Fprintf(&moduleTable, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(module.Name), html.EscapeString(module.Policy), html.EscapeString(state), html.EscapeString(module.Reason))
	}
	moduleTable.WriteString("</table>")
	action := "No action required."
	if semantic.OverallState != statusmodel.Healthy {
		action = "Action required: open <a href=\"/security.html\">Lab checks</a> for the reason and suggested next step."
	}
	observedAt := strings.TrimSpace(evidence.GeneratedAt)
	if evidence.Status != nil && strings.TrimSpace(evidence.Status.ObservedAt) != "" {
		observedAt = strings.TrimSpace(evidence.Status.ObservedAt)
	}
	if observedAt == "" {
		observedAt = "not recorded"
	}
	return fmt.Sprintf("<p>Here is your Boetticher lab at a glance. Use the links above for services, recovery, and the guides.</p><p>Lab revision: <code>%s</code></p><h2>Lab result: %s</h2><p>Gateway: %s · observed: %s</p><p>%s</p>%s<h2>Useful links</h2><p><a href=\"%s\">Proxmox</a> · <a href=\"https://monitor.%s\">Pulse monitoring</a> · <a href=\"https://portal.%s\">Portal</a> · <a href=\"https://dns.%s\">DNS</a></p>", html.EscapeString(revision), html.EscapeString(humanOverallResult(semantic.OverallState)), html.EscapeString(gateway), html.EscapeString(observedAt), action, moduleTable.String(), html.EscapeString("https://proxmox."+s.Network.Domain+":8006"), html.EscapeString(s.Network.Domain), html.EscapeString(s.Network.Domain), html.EscapeString(s.Network.Domain))
}

func loggingSummary(s model.Site, evidence Evidence) string {
	collector := logging.CollectorName
	address := logging.CollectorAddress
	for _, component := range s.PlatformComponents() {
		if component.Name == logging.CollectorName {
			collector = component.Hostname
			address = component.Address
			break
		}
	}
	expectedSources := 0
	for _, component := range s.PlatformComponents() {
		if component.Logging && component.Name != logging.CollectorName {
			expectedSources++
		}
	}
	observed := "FAIL"
	for _, result := range evidence.Results {
		if strings.Contains(strings.ToLower(result.Name), "logging") {
			observed = humanResult(result.Status)
			break
		}
	}
	return fmt.Sprintf("<h2>Logging</h2><table><tr><th>Collector</th><td>%s (%s)</td></tr><tr><th>Receiver</th><td><code>https://logs.%s:%d</code> with mTLS</td></tr><tr><th>Persistent storage</th><td><code>%s</code> · %d GiB · prefer-data-disk · backup=false</td></tr><tr><th>Retention</th><td>SplitMode=host · MaxUse=%s · KeepFree=%s</td></tr><tr><th>Expected upload sources</th><td>%d</td></tr><tr><th>Latest result</th><td>%s</td></tr></table>", html.EscapeString(collector), html.EscapeString(address), html.EscapeString(s.Network.Domain), logging.CollectorPort, html.EscapeString(logging.RemoteJournalPath), logging.CollectorVolumeGiB, html.EscapeString(logging.CollectorMaxUse), html.EscapeString(logging.CollectorKeepFree), expectedSources, html.EscapeString(observed))
}

func inventory(s model.Site, revision string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Lab revision: <code>%s</code></p><p>Boetticher looks after its platform guests. Your own entries are shown here for context only.</p><table><tr><th>Host</th><th>Looked after by</th><th>Zone</th><th>Address</th><th>Role</th><th>Tags</th><th>Monitoring</th><th>Backup</th></tr>", html.EscapeString(revision))
	for _, m := range sortedComponents(s) {
		ownership := "you / shown for context"
		if m.ProductOwned {
			ownership = "Boetticher platform"
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>", html.EscapeString(m.Hostname), html.EscapeString(ownership), html.EscapeString(m.Zone), html.EscapeString(m.Address), html.EscapeString(m.Role), html.EscapeString(strings.Join(m.Tags, ";")), checkMark(m.Monitoring), checkMark(m.Backup))
	}
	b.WriteString("</table>")
	return b.String()
}

func network(s model.Site, revision string) string {
	var b strings.Builder
	gateway := "external firewall contract"
	diagram := "HOME / upstream\n  |\nProxmox (MGMT 10.10.99.5)\n  `-- vmbr1 (VLAN-aware physical trunk)\n      +-- TRANSIT VLAN 5\n      +-- INFRA VLAN 10\n      +-- SERVERS VLAN 20\n      +-- TRUSTED VLAN 30\n      +-- SANDBOX VLAN 40\n      `-- MGMT VLAN 99"
	if s.Gateway.Mode == model.GatewayModeManaged {
		gateway = "Debian lab-fw-01 (nftables + Kea)"
		diagram = "HOME / upstream\n  |\nProxmox (MGMT 10.10.99.5)\n  +-- managed gateway vNICs: WAN, TRANSIT, INFRA, SERVERS, TRUSTED, SANDBOX, MGMT\n  `-- vmbr1 (VLAN-aware internal bridge)\n      +-- TRANSIT VLAN 5\n      +-- INFRA VLAN 10\n      +-- SERVERS VLAN 20\n      +-- TRUSTED VLAN 30\n      +-- SANDBOX VLAN 40\n      `-- MGMT VLAN 99"
	}
	fmt.Fprintf(&b, "<p>Lab revision: <code>%s</code></p><p>Gateway: <strong>%s</strong>.</p><pre>%s</pre><table><tr><th>Zone</th><th>VLAN</th><th>Network</th><th>Gateway</th><th>DHCP mode</th></tr>", html.EscapeString(revision), html.EscapeString(gateway), html.EscapeString(diagram))
	for _, z := range s.Network.Zones {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(z.Name), z.VLAN, html.EscapeString(z.Network), html.EscapeString(z.Gateway), html.EscapeString(z.AddressMode))
	}
	b.WriteString("</table>")
	return b.String()
}

func services(s model.Site, revision string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<p>Lab revision: <code>%s</code></p><p>Use Boetticher and each product's own UI for normal administration. Appliance SSH is an internal deployment path, not an everyday service interface.</p><table><tr><th>Service</th><th>URL</th><th>mTLS</th></tr>", html.EscapeString(revision))
	for _, m := range sortedComponents(s) {
		if !m.ProductOwned || (m.URL == "" && !m.SSHManaged) {
			continue
		}
		url := m.URL
		if url == "" {
			url = "—"
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(m.Role), html.EscapeString(url), checkMark(m.MTLS))
	}
	b.WriteString("</table>")
	return b.String()
}

func access(s model.Site, revision string, physical networkmodel.Discovery) string {
	var b strings.Builder
	boundary := "<p>Normal SSH and hands-on changes to Boetticher appliances are not part of the everyday workflow. SSH and Ansible are internal deployment plumbing.</p>"
	if s.Gateway.Mode == model.GatewayModeExternal {
		boundary = "<p>The external firewall is yours to run. Configure, administer, and recover it through its own interface; Boetticher gives you the settings it needs but does not manage the appliance.</p>"
	}
	fmt.Fprintf(&b, "<p>Lab revision: <code>%s</code></p><h2>Your usual ways in</h2><ul><li>Use the Boetticher CLI for platform settings, lifecycle, and logs.</li><li>Use the native product UI or API where a service provides one.</li><li>Use this portal for a quick lab overview and the latest check results.</li><li>Use Proxmox console or exec access as the recovery route when needed.</li></ul>%s", html.EscapeString(revision), boundary)
	if s.BootstrapAddress == "" {
		b.WriteString("<p class=\"notice\">Break-glass Proxmox endpoint: not configured.</p>")
	} else {
		fmt.Fprintf(&b, "<p>Break-glass Proxmox endpoint: <code>%s</code> · use the Proxmox console/exec path.</p>", html.EscapeString(s.BootstrapAddress))
	}
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
	fmt.Fprintf(&b, "<h2>Physical network details</h2><p>Upstream address: <code>%s</code></p><table><tr><th>Role</th><th>Interface</th><th>Permanent MAC</th><th>PCI</th><th>Driver</th><th>Model</th><th>Speed</th><th>Carrier</th><th>Bridge</th><th>Addresses</th></tr>", html.EscapeString(physical.BootstrapAddress))
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
	fmt.Fprintf(&b, "<p>Lab revision: <code>%s</code></p><p>A small checklist of the platform's protective settings and latest checks. Live telemetry belongs to Pulse monitoring.</p><table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>", html.EscapeString(revision))
	for _, result := range evidence.Results {
		resultStatus := humanResult(result.Status)
		class := strings.ToLower(resultStatus)
		fmt.Fprintf(&b, "<tr><td>%s</td><td class=\"%s\">%s</td><td>%s</td></tr>", html.EscapeString(result.Name), html.EscapeString(class), html.EscapeString(resultStatus), html.EscapeString(result.Detail))
	}
	if len(evidence.Results) == 0 {
		b.WriteString("<tr><td colspan=\"3\">FAIL — no recent check results are available; run boetticher verify.</td></tr>")
	}
	b.WriteString("</table>")
	return b.String()
}

func humanResult(value string) string {
	value = strings.TrimSpace(strings.ToUpper(value))
	if value == "PASS" || value == "STATIC PASS" {
		return "PASS"
	}
	return "FAIL"
}

func humanOverallResult(value statusmodel.OperatorState) string {
	if value == statusmodel.Healthy {
		return "PASS"
	}
	return "FAIL"
}

func pki(s model.Site, revision string) string {
	return fmt.Sprintf("<p>Lab revision: <code>%s</code></p><table><tr><th>Certificate issuer</th><th>Common name</th><th>Fingerprint</th><th>Expiry</th></tr><tr><td>Root CA</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr><tr><td>Issuing CA</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr></table><p>Endpoint and CA private keys are not rendered here.</p>", html.EscapeString(revision), html.EscapeString(s.PKI.RootCommonName), html.EscapeString(s.PKI.RootFingerprint), html.EscapeString(s.PKI.RootExpiry), html.EscapeString(s.PKI.IssuingCommonName), html.EscapeString(s.PKI.IssuingFingerprint), html.EscapeString(s.PKI.IssuingExpiry))
}

func recovery(s model.Site, revision string, evidence Evidence) string {
	ids := make([]string, 0)
	for _, component := range s.PlatformComponents() {
		if component.VMID != 0 && component.Backup {
			ids = append(ids, strconv.Itoa(component.VMID))
		}
	}
	sort.Strings(ids)
	return fmt.Sprintf("<p>Lab revision: <code>%s</code></p><h2>Keep these</h2><ul><li>Private site repository with your lab settings and encrypted secrets.</li><li>An independent recovery copy of the age private identity.</li></ul><h2>Storage</h2><p>Storage profile: <code>%s</code>. Same-disk backups are not disaster recovery.</p><p>Platform backup job: <code>boetticher-platform</code> for Boetticher guest IDs %s. Your workloads use their own backup plan.</p><p>Age recovery and backup freshness appear here when the running lab can report them.</p>", html.EscapeString(revision), html.EscapeString(s.StorageProfile), html.EscapeString(strings.Join(ids, ", ")))
}

func copyDocs(outputDir, docsDir, revision string) error {
	destination := filepath.Join(outputDir, "docs")
	if err := pathguard.MkdirAll(destination, 0755); err != nil {
		return err
	}
	entries := []string{}
	if docsDir != "" {
		if err := pathguard.ValidateNoSymlinkComponents(docsDir); err != nil {
			return fmt.Errorf("refuse symlinked portal docs root: %w", err)
		}
		if err := filepath.Walk(docsDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".md") {
				entries = append(entries, path)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("walk portal docs: %w", err)
		}
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
		if err := pathguard.ValidateNoSymlinkComponents(source); err != nil {
			return fmt.Errorf("refuse symlinked portal doc %s: %w", source, err)
		}
		data, err := pathguard.ReadFile(source)
		if err != nil {
			return err
		}
		pagePath := filepath.Join(destination, filepath.FromSlash(name))
		if err := writePage(pagePath, page(filepath.ToSlash(rel), "<pre>"+html.EscapeString(stripFrontMatter(string(data)))+"</pre>")); err != nil {
			return err
		}
		fmt.Fprintf(&index, "<li><a href=\"%s\">%s</a></li>", html.EscapeString(filepath.ToSlash(name)), html.EscapeString(filepath.ToSlash(rel)))
	}
	index.WriteString("</ul>")
	return writePage(filepath.Join(destination, "index.html"), page("Guides", index.String()))
}

// stripFrontMatter keeps the portal's plain-text guide view useful when the
// same Markdown file also acts as a Jekyll page for the public docs site.
func stripFrontMatter(document string) string {
	const delimiter = "---\n"
	if !strings.HasPrefix(document, delimiter) {
		return document
	}
	rest := document[len(delimiter):]
	end := strings.Index(rest, "\n"+delimiter)
	if end < 0 {
		return document
	}
	return rest[end+len("\n"+delimiter):]
}

func sortedComponents(s model.Site) []model.Component {
	copyComponents := s.PlatformComponents()
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
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	return pathguard.WriteFileWithParentMode(path, []byte(content), 0644, 0755)
}
