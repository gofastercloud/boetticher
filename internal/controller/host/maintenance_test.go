package host

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const sampleSources = `BOETTICHER_SOURCE_FILE=/etc/apt/sources.list.d/debian.sources
Types: deb
URIs: http://deb.debian.org/debian/
Suites: trixie trixie-updates
Components: main contrib non-free-firmware
Signed-By: -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mQINBGenterprise.proxmox.com-not-a-uri
 -----END PGP PUBLIC KEY BLOCK-----

BOETTICHER_SOURCE_FILE=/etc/apt/sources.list.d/pve-enterprise.sources
Types: deb
URIs: https://enterprise.proxmox.com/debian/pve
Suites: trixie
Components: pve-enterprise
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: no

BOETTICHER_SOURCE_FILE=/etc/apt/sources.list.d/old.list
# deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise
deb [arch=amd64 signed-by=/k.gpg] http://download.proxmox.com/debian/ceph-squid trixie no-subscription

BOETTICHER_SOURCE_FILE=/etc/apt/sources.list.d/boetticher-pve-no-subscription.sources
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription

BOETTICHER_SUBSCRIPTION=notfound
`

func TestRepositoryPolicyAcceptsDisabledEnterpriseAndNoSubscription(t *testing.T) {
	state := ParseAptRepositories([]byte(sampleSources))
	if state.Subscription != "notfound" || len(state.Sources) != 4 {
		t.Fatalf("state=%+v", state)
	}
	if state.Sources[1].Enabled || !state.Sources[0].Enabled || state.Sources[2].URIs[0] != "http://download.proxmox.com/debian/ceph-squid" {
		t.Fatalf("sources=%+v", state.Sources)
	}
	pve, err := CheckRepositoryPolicy(state)
	if err != nil || len(pve) != 1 || pve[0].Components[0] != "pve-no-subscription" {
		t.Fatalf("pve=%+v err=%v", pve, err)
	}
}

func TestRepositoryPolicyRefusesEnabledEnterpriseWithoutSubscription(t *testing.T) {
	enabled := strings.Replace(sampleSources, "Enabled: no\n", "", 1)
	_, err := CheckRepositoryPolicy(ParseAptRepositories([]byte(enabled)))
	if err == nil || !strings.Contains(err.Error(), "enterprise repository is enabled without an active subscription") || !strings.Contains(err.Error(), "pve-enterprise.sources") || !strings.Contains(err.Error(), "does not rewrite") {
		t.Fatalf("err=%v", err)
	}
	active := strings.Replace(enabled, "BOETTICHER_SUBSCRIPTION=notfound", "BOETTICHER_SUBSCRIPTION=active", 1)
	if pve, err := CheckRepositoryPolicy(ParseAptRepositories([]byte(active))); err != nil || len(pve) != 2 {
		t.Fatalf("subscribed pve=%+v err=%v", pve, err)
	}
	listEnabled := "BOETTICHER_SOURCE_FILE=/etc/apt/sources.list\ndeb https://enterprise.proxmox.com/debian/pve trixie pve-enterprise\nBOETTICHER_SUBSCRIPTION=\n"
	if _, err := CheckRepositoryPolicy(ParseAptRepositories([]byte(listEnabled))); err == nil || !strings.Contains(err.Error(), "status unknown") {
		t.Fatalf("one-line enterprise err=%v", err)
	}
	if _, err := CheckRepositoryPolicy(ParseAptRepositories([]byte("BOETTICHER_SUBSCRIPTION=notfound\n"))); err == nil || !strings.Contains(err.Error(), "host apply") {
		t.Fatalf("missing pve repository err=%v", err)
	}
}

func TestSimulatedUpgradeAndPackageDiff(t *testing.T) {
	plan := ParseSimulatedUpgrade([]byte(`NOTE: This is only a simulation!
Inst pve-manager [9.2.21] (9.2.22 Proxmox:9.2/stable [all])
Inst proxmox-kernel-7.0.15-1-pve-signed (7.0.15-1 Proxmox:9.2/stable [amd64])
Inst libc6 [2.41-12] (2.41-13 Debian:13.2/stable [amd64]) []
Remv old-tool [1.0]
Conf pve-manager (9.2.22 Proxmox:9.2/stable [all])
`))
	if plan.Count() != 4 || len(plan.Upgrades) != 2 || len(plan.Installs) != 1 || len(plan.Removals) != 1 || plan.Upgrades[0].From != "9.2.21" || plan.Upgrades[0].To != "9.2.22" {
		t.Fatalf("plan=%+v", plan)
	}
	if reasons := plan.RebootReasons(); strings.Join(reasons, ",") != "libc6,proxmox-kernel-7.0.15-1-pve-signed" {
		t.Fatalf("reasons=%v", reasons)
	}
	if len(plan.ProtectedRemovals()) != 0 || len(ParseSimulatedUpgrade([]byte("Remv proxmox-ve [9.1]\n")).ProtectedRemovals()) != 1 {
		t.Fatal("protected removal classification")
	}
	before := ParsePackageSnapshot([]byte("ii \tpve-manager\t9.2.21\nii \told-tool\t1.0\nrc \tgone\t0.1\n"))
	after := ParsePackageSnapshot([]byte("ii \tpve-manager\t9.2.22\nii \tproxmox-kernel-7.0.15-1-pve-signed\t7.0.15-1\n"))
	diff := DiffPackages(before, after)
	if diff.Count() != 3 || diff.Upgrades[0].Name != "pve-manager" || diff.Installs[0].Name != "proxmox-kernel-7.0.15-1-pve-signed" || diff.Removals[0].Name != "old-tool" {
		t.Fatalf("diff=%+v", diff)
	}
}

func TestRebootStateAndRefreshProblems(t *testing.T) {
	state, err := ParseRebootState([]byte("BOETTICHER_RUNNING_KERNEL=7.0.14-16-pve\nBOETTICHER_NEWEST_KERNEL=7.0.15-1-pve\nBOETTICHER_REBOOT_REQUIRED=0\n"))
	if err != nil || !state.Required() || !strings.Contains(state.Reason(), "newest installed 7.0.15-1-pve") {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	current, _ := ParseRebootState([]byte("BOETTICHER_RUNNING_KERNEL=7.0.14-16-pve\nBOETTICHER_NEWEST_KERNEL=7.0.14-16-pve\nBOETTICHER_REBOOT_REQUIRED=0\n"))
	if current.Required() {
		t.Fatalf("current=%+v", current)
	}
	if _, err := ParseRebootState([]byte("garbage")); err == nil {
		t.Fatal("unknown reboot state was accepted")
	}
	if problems := RefreshProblems([]byte("Hit:1 http://deb.debian.org\nErr:2 https://enterprise.proxmox.com\nW: Failed to fetch https://enterprise.proxmox.com/... 401 Unauthorized\n")); len(problems) != 1 {
		t.Fatalf("problems=%v", problems)
	}
}

func TestGuestBootPolicyParsingAndStartOrder(t *testing.T) {
	parse := func(guest Guest, config string) GuestBootPolicy {
		t.Helper()
		policy, err := ParseGuestBootPolicy(guest, []byte(config))
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
	policies := []GuestBootPolicy{
		parse(Guest{VMID: 290, Type: "qemu"}, `{"onboot":1}`),
		parse(Guest{VMID: 280, Type: "qemu"}, `{"onboot":1,"startup":"order=1,up=60,down=120"}`),
		parse(Guest{VMID: 120, Type: "lxc"}, `{"onboot":"1","startup":"3"}`),
		parse(Guest{VMID: 501, Type: "lxc"}, `{"startup":"order=2"}`),
	}
	SortByStartOrder(policies)
	var order []int
	for _, policy := range policies {
		order = append(order, policy.VMID)
	}
	if fmt.Sprint(order) != "[280 501 120 290]" {
		t.Fatalf("order=%v", order)
	}
	if !policies[0].OnBoot || policies[0].Up != 60 || policies[0].Down != 120 || policies[1].OnBoot || !policies[2].OnBoot {
		t.Fatalf("policies=%+v", policies)
	}
	if _, err := GuestConfigCommand("node;rm", Guest{VMID: 1, Type: "qemu"}); err == nil {
		t.Fatal("unsafe node accepted")
	}
	if command, err := GuestConfigCommand("lab-proxmox-01", Guest{VMID: 501, Type: "lxc"}); err != nil || command != "pvesh get /nodes/lab-proxmox-01/lxc/501/config --output-format json" {
		t.Fatalf("command=%q err=%v", command, err)
	}
}

type stubRunner map[string]Result

func (s stubRunner) Run(_ context.Context, command string) (Result, error) { return s[command], nil }

func TestReadGuestsTreatsUnknownAsError(t *testing.T) {
	for _, output := range []string{"", "null", "{}", "not json"} {
		if _, err := ReadGuests(context.Background(), stubRunner{cmdGuests: {Stdout: []byte(output)}}); err == nil {
			t.Fatalf("guest listing %q was treated as known", output)
		}
	}
	guests, err := ReadGuests(context.Background(), stubRunner{cmdGuests: {Stdout: []byte(`[{"type":"node","node":"n"},{"type":"qemu","vmid":280,"name":"fw","status":"running"}]`)}})
	if err != nil || len(guests) != 1 || guests[0].VMID != 280 {
		t.Fatalf("guests=%+v err=%v", guests, err)
	}
	if empty, err := ReadGuests(context.Background(), stubRunner{cmdGuests: {Stdout: []byte(`[]`)}}); err != nil || len(empty) != 0 {
		t.Fatalf("empty=%v err=%v", empty, err)
	}
}
