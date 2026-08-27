package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestParseKeaLeaseCSVQualifiesActiveNamesByZone(t *testing.T) {
	plan, err := firewall.PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n" +
		"10.10.30.104,aa:bb,,86400,0,2,1,1,laptop,0,\n" +
		"10.10.40.112,aa:cc,,86400,0,3,1,1,kali.sandbox.lab.home.arpa.,0,\n" +
		"10.10.30.123,aa:dd,,86400,0,2,1,1,expired,2,\n")
	leases, err := parseKeaLeaseCSV(data, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d active leases, want 2: %#v", len(leases), leases)
	}
	if leases[0].Zone != "TRUSTED" || leases[0].FQDN != "laptop.trusted.lab.home.arpa" {
		t.Fatalf("simple hostname was not qualified by zone: %#v", leases[0])
	}
	if leases[1].Zone != "SANDBOX" || leases[1].FQDN != "kali.sandbox.lab.home.arpa" {
		t.Fatalf("qualified hostname was not normalized: %#v", leases[1])
	}
}

func TestParseKeaLeaseCSVRejectsMissingContractColumns(t *testing.T) {
	plan, err := firewall.PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeaLeaseCSV([]byte("address,hostname\n10.10.30.1,test\n"), plan); err == nil {
		t.Fatal("lease parser accepted an incomplete Kea CSV header")
	}
}
