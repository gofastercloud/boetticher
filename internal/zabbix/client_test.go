package zabbix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

type apiFixture struct {
	requests     []string
	nextID       int
	hosts        map[string]zabbixObject
	templates    map[string]zabbixObject
	items        map[string]zabbixObject
	dashboards   map[string]zabbixObject
	unownedHosts map[string]bool
	userObjects  int
}

func newAPIFixture() *apiFixture {
	return &apiFixture{
		nextID: 1000, hosts: map[string]zabbixObject{}, templates: map[string]zabbixObject{}, items: map[string]zabbixObject{}, dashboards: map[string]zabbixObject{}, unownedHosts: map[string]bool{},
	}
}

func (f *apiFixture) handler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
		ID     int            `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.requests = append(f.requests, request.Method)
	result := f.result(request.Method, request.Params)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": result, "id": request.ID})
}

func (f *apiFixture) result(method string, params map[string]any) any {
	switch method {
	case "user.login":
		return "fixture-token"
	case "hostgroup.get":
		return []map[string]string{{"groupid": "42"}}
	case "hostgroup.create":
		return map[string]any{"groupids": []string{"42"}}
	case "template.get":
		key := filterValue(params, "host")
		if object, ok := f.templates[key]; ok {
			return []zabbixObject{object}
		}
		return []zabbixObject{}
	case "template.create":
		key := stringValue(params, "host")
		object := zabbixObject{ID: f.newID(), Host: key, Name: stringValue(params, "name"), Tags: apiTags()}
		f.templates[key] = object
		return map[string]any{"templateids": []string{object.ID}}
	case "template.update":
		return map[string]any{"templateids": []string{stringValue(params, "templateid")}}
	case "host.get":
		key := filterValue(params, "host")
		if f.unownedHosts[key] {
			return []zabbixObject{{HostID: "550", Host: key, Name: key}}
		}
		if object, ok := f.hosts[key]; ok {
			return []zabbixObject{object}
		}
		return []zabbixObject{}
	case "host.create":
		key := stringValue(params, "host")
		object := zabbixObject{HostID: f.newID(), Host: key, Name: stringValue(params, "name"), Tags: apiTags()}
		f.hosts[key] = object
		return map[string]any{"hostids": []string{object.HostID}}
	case "host.update":
		return map[string]any{"hostids": []string{stringValue(params, "hostid")}}
	case "item.get":
		key := filterValue(params, "key_")
		if object, ok := f.items[key]; ok {
			return []zabbixObject{object}
		}
		return []zabbixObject{}
	case "item.create":
		key := stringValue(params, "key_")
		object := zabbixObject{ItemID: f.newID(), Name: stringValue(params, "name"), Tags: apiTags()}
		f.items[key] = object
		return map[string]any{"itemids": []string{object.ItemID}}
	case "item.update":
		return map[string]any{"itemids": []string{stringValue(params, "itemid")}}
	case "dashboard.get":
		key := filterValue(params, "name")
		if object, ok := f.dashboards[key]; ok {
			return []zabbixObject{object}
		}
		return []zabbixObject{}
	case "dashboard.create":
		key := stringValue(params, "name")
		object := zabbixObject{DashboardID: f.newID(), Name: key}
		f.dashboards[key] = object
		return map[string]any{"dashboardids": []string{object.DashboardID}}
	case "dashboard.update":
		return map[string]any{"dashboardids": []string{stringValue(params, "dashboardid")}}
	default:
		return map[string]any{}
	}
}

func (f *apiFixture) newID() string {
	f.nextID++
	return fmt.Sprintf("%d", f.nextID)
}

func filterValue(params map[string]any, key string) string {
	filter, _ := params["filter"].(map[string]any)
	values, _ := filter[key].([]any)
	if len(values) == 0 {
		return ""
	}
	return stringValue(map[string]any{"value": values[0]}, "value")
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func TestReconcileCreatesOnlyNamespacedPlatformObjects(t *testing.T) {
	fixture := newAPIFixture()
	fixture.userObjects = 4
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	client, err := NewClient(ClientConfig{BaseURL: server.URL, User: "Admin", Password: "fixture", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Reconcile(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, object := range plan.Objects {
		if object.Kind == "template" && fixture.templates[object.Key].Name != object.Name {
			t.Fatalf("template %s was not created", object.Name)
		}
		if object.Kind == "dashboard" && fixture.dashboards[object.Name].Name != object.Name {
			t.Fatalf("dashboard %s was not created", object.Name)
		}
	}
	if len(fixture.hosts) != len(plan.Components) {
		t.Fatalf("created %d platform hosts, want %d", len(fixture.hosts), len(plan.Components))
	}
	if fixture.userObjects != 4 {
		t.Fatal("unrelated user Zabbix objects were changed")
	}
	if !contains(fixture.requests, "dashboard.create") || !contains(fixture.requests, "item.create") {
		t.Fatalf("reconciliation did not create dashboards and checks: %v", fixture.requests)
	}
}

func TestReconcileRefusesToUpdateUnownedHost(t *testing.T) {
	fixture := newAPIFixture()
	fixture.unownedHosts["lab-dns-01"] = true
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()
	client, err := NewClient(ClientConfig{BaseURL: server.URL, User: "Admin", Password: "fixture", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Reconcile(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "unowned Zabbix host lab-dns-01") {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	if contains(fixture.requests, "host.update") {
		t.Fatal("reconciliation updated an unowned host")
	}
}

func TestPlatformItemsAndHostsRemainDeterministic(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Components) != 6 || len(plan.TemplateItems) < 6 {
		t.Fatalf("incomplete platform monitoring plan: %#v", plan)
	}
	for _, item := range plan.TemplateItems {
		if item.Tags[0] != ownershipTag {
			t.Fatalf("template item is outside ownership namespace: %#v", item)
		}
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
