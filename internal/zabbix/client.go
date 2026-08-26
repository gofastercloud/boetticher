package zabbix

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
)

const ownershipTag = "boetticher/platform"

type ClientConfig struct {
	BaseURL       string
	User          string
	Password      string
	CAFile        string
	CAPEM         string
	ClientCertPEM string
	ClientKeyPEM  string
	ServerName    string
	Insecure      bool
	Timeout       time.Duration
	HTTP          *http.Client
}

type Client struct {
	baseURL  string
	user     string
	password string
	auth     string
	http     *http.Client
	nextID   int
}

type APIError struct {
	Code    int
	Message string
	Data    string
}

func (e *APIError) Error() string {
	if e.Data == "" {
		return fmt.Sprintf("Zabbix API %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("Zabbix API %d: %s: %s", e.Code, e.Message, e.Data)
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.BaseURL == "" || config.User == "" || config.Password == "" {
		return nil, errors.New("Zabbix URL, user, and password are required")
	}
	if config.HTTP != nil {
		return &Client{baseURL: strings.TrimRight(config.BaseURL, "/"), user: config.User, password: config.Password, http: config.HTTP, nextID: 1}, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.Insecure, ServerName: config.ServerName} // #nosec G402 -- only enabled by explicit operator choice.
	if config.CAFile != "" {
		data, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read Zabbix CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("Zabbix CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	if config.CAPEM != "" {
		if transport.TLSClientConfig.RootCAs == nil {
			transport.TLSClientConfig.RootCAs = x509.NewCertPool()
		}
		if !transport.TLSClientConfig.RootCAs.AppendCertsFromPEM([]byte(config.CAPEM)) {
			return nil, errors.New("Zabbix CA PEM contains no certificates")
		}
	}
	if config.ClientCertPEM != "" || config.ClientKeyPEM != "" {
		certificate, err := tls.X509KeyPair([]byte(config.ClientCertPEM), []byte(config.ClientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("load Zabbix client certificate: %w", err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{baseURL: strings.TrimRight(config.BaseURL, "/"), user: config.User, password: config.Password, http: &http.Client{Transport: transport, Timeout: timeout}, nextID: 1}, nil
}

func (c *Client) Reconcile(ctx context.Context, plan Plan) error {
	if !plan.PlatformOnly || plan.ManagedBy != "boetticher" || plan.HostGroup != PlatformHostGroup {
		return errors.New("refusing to reconcile a non-boetticher Zabbix plan")
	}
	if err := c.login(ctx); err != nil {
		return err
	}
	groupID, err := c.ensureHostGroup(ctx, plan.HostGroup)
	if err != nil {
		return err
	}
	templateIDs, err := c.ensureTemplates(ctx, plan, groupID)
	if err != nil {
		return err
	}
	hostIDs, err := c.ensureHosts(ctx, plan, groupID, templateIDs)
	if err != nil {
		return err
	}
	if err := c.ensureTemplateItems(ctx, plan, templateIDs); err != nil {
		return err
	}
	if err := c.ensureChecks(ctx, plan, hostIDs); err != nil {
		return err
	}
	return c.ensureDashboards(ctx, plan)
}

func (c *Client) login(ctx context.Context) error {
	var result string
	if err := c.call(ctx, "user.login", map[string]any{"username": c.user, "password": c.password}, &result); err != nil {
		return fmt.Errorf("authenticate to Zabbix API: %w", err)
	}
	if result == "" {
		return errors.New("Zabbix API returned an empty authentication token")
	}
	c.auth = result
	return nil
}

func (c *Client) ensureHostGroup(ctx context.Context, name string) (string, error) {
	var groups []struct {
		GroupID string `json:"groupid"`
	}
	if err := c.call(ctx, "hostgroup.get", map[string]any{"output": []string{"groupid", "name"}, "filter": map[string]any{"name": []string{name}}}, &groups); err != nil {
		return "", fmt.Errorf("read Zabbix host group: %w", err)
	}
	if len(groups) > 0 && groups[0].GroupID != "" {
		return groups[0].GroupID, nil
	}
	var created struct {
		GroupIDs []string `json:"groupids"`
	}
	if err := c.call(ctx, "hostgroup.create", map[string]any{"name": name}, &created); err != nil {
		return "", fmt.Errorf("create Zabbix host group: %w", err)
	}
	if len(created.GroupIDs) != 1 {
		return "", errors.New("Zabbix host group create returned no group ID")
	}
	return created.GroupIDs[0], nil
}

type zabbixTag struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type zabbixObject struct {
	ID          string      `json:"templateid"`
	HostID      string      `json:"hostid"`
	ItemID      string      `json:"itemid"`
	DashboardID string      `json:"dashboardid"`
	Host        string      `json:"host"`
	Name        string      `json:"name"`
	Tags        []zabbixTag `json:"tags"`
}

func zabbixOwned(tags []zabbixTag) bool {
	for _, tag := range tags {
		if tag.Tag == ownershipTag && tag.Value == "managed" {
			return true
		}
	}
	return false
}

func apiTags() []zabbixTag { return []zabbixTag{{Tag: ownershipTag, Value: "managed"}} }

func (c *Client) ensureTemplates(ctx context.Context, plan Plan, groupID string) (map[string]string, error) {
	ids := map[string]string{}
	for _, object := range plan.Objects {
		if object.Kind != "template" {
			continue
		}
		var templates []zabbixObject
		if err := c.call(ctx, "template.get", map[string]any{"output": []string{"templateid", "host", "name"}, "selectTags": "extend", "filter": map[string]any{"host": []string{object.Key}}}, &templates); err != nil {
			return nil, fmt.Errorf("read Zabbix template %s: %w", object.Name, err)
		}
		payload := map[string]any{"host": object.Key, "name": object.Name, "groups": []map[string]string{{"groupid": groupID}}, "tags": apiTags()}
		if len(templates) == 0 {
			var created struct {
				IDs []string `json:"templateids"`
			}
			if err := c.call(ctx, "template.create", payload, &created); err != nil {
				return nil, fmt.Errorf("create Zabbix template %s: %w", object.Name, err)
			}
			if len(created.IDs) != 1 {
				return nil, fmt.Errorf("Zabbix template %s create returned no ID", object.Name)
			}
			ids[object.Name] = created.IDs[0]
			continue
		}
		if !zabbixOwned(templates[0].Tags) {
			return nil, fmt.Errorf("refusing to update unowned Zabbix template %s", object.Name)
		}
		payload["templateid"] = templates[0].ID
		if err := c.call(ctx, "template.update", payload, &struct{}{}); err != nil {
			return nil, fmt.Errorf("update Zabbix template %s: %w", object.Name, err)
		}
		ids[object.Name] = templates[0].ID
	}
	return ids, nil
}

func (c *Client) ensureHosts(ctx context.Context, plan Plan, groupID string, templateIDs map[string]string) (map[string]string, error) {
	ids := map[string]string{}
	for _, component := range plan.Components {
		var hosts []zabbixObject
		if err := c.call(ctx, "host.get", map[string]any{"output": []string{"hostid", "host", "name"}, "selectTags": "extend", "filter": map[string]any{"host": []string{component.Hostname}}}, &hosts); err != nil {
			return nil, fmt.Errorf("read Zabbix host %s: %w", component.Name, err)
		}
		templates := templateLinks(component, templateIDs)
		interfaces := []map[string]any{{"type": 1, "main": 1, "useip": 1, "ip": component.Address, "dns": "", "port": "10050"}}
		// The managed gateway is an ordinary Linux host monitored by Agent 2.
		payload := map[string]any{"host": component.Hostname, "name": component.Name, "groups": []map[string]string{{"groupid": groupID}}, "interfaces": interfaces, "tags": apiTags(), "templates": templates}
		if len(hosts) == 0 {
			var created struct {
				IDs []string `json:"hostids"`
			}
			if err := c.call(ctx, "host.create", payload, &created); err != nil {
				return nil, fmt.Errorf("create Zabbix host %s: %w", component.Name, err)
			}
			if len(created.IDs) != 1 {
				return nil, fmt.Errorf("Zabbix host %s create returned no ID", component.Name)
			}
			ids[component.Name] = created.IDs[0]
			continue
		}
		if !zabbixOwned(hosts[0].Tags) {
			return nil, fmt.Errorf("refusing to update unowned Zabbix host %s", component.Name)
		}
		payload["hostid"] = hosts[0].HostID
		if err := c.call(ctx, "host.update", payload, &struct{}{}); err != nil {
			return nil, fmt.Errorf("update Zabbix host %s: %w", component.Name, err)
		}
		ids[component.Name] = hosts[0].HostID
	}
	return ids, nil
}

func templateLinks(component model.Component, templateIDs map[string]string) []map[string]string {
	result := make([]map[string]string, 0, 2)
	if component.Role != "Debian firewall" {
		if id := templateIDs["boetticher Linux platform"]; id != "" {
			result = append(result, map[string]string{"templateid": id})
		}
	}
	if component.Name == model.DefaultProxmoxNode {
		if id := templateIDs["boetticher Proxmox platform"]; id != "" {
			result = append(result, map[string]string{"templateid": id})
		}
	}
	if component.Role == "Debian firewall" {
		if id := templateIDs["boetticher gateway platform"]; id != "" {
			result = append(result, map[string]string{"templateid": id})
		}
	}
	return result
}

func (c *Client) ensureTemplateItems(ctx context.Context, plan Plan, templateIDs map[string]string) error {
	for _, item := range plan.TemplateItems {
		templateID := templateIDs[item.Template]
		if templateID == "" {
			return fmt.Errorf("template item %s references unknown template %s", item.Name, item.Template)
		}
		var existing []zabbixObject
		if err := c.call(ctx, "item.get", map[string]any{"output": []string{"itemid", "name", "key_"}, "selectTags": "extend", "templateids": []string{templateID}, "filter": map[string]any{"key_": []string{item.Key}}}, &existing); err != nil {
			return fmt.Errorf("read Zabbix template item %s: %w", item.Name, err)
		}
		payload := map[string]any{"hostid": templateID, "name": item.Name, "key_": item.Key, "type": 0, "value_type": item.ValueType, "delay": item.Delay, "tags": apiTags()}
		if strings.HasPrefix(item.Key, "net.tcp.service[") {
			payload["type"] = 3
		}
		if len(existing) == 0 {
			var created struct {
				IDs []string `json:"itemids"`
			}
			if err := c.call(ctx, "item.create", payload, &created); err != nil {
				return fmt.Errorf("create Zabbix template item %s: %w", item.Name, err)
			}
			continue
		}
		if !zabbixOwned(existing[0].Tags) {
			return fmt.Errorf("refusing to update unowned Zabbix template item %s", item.Name)
		}
		payload["itemid"] = existing[0].ItemID
		if err := c.call(ctx, "item.update", payload, &struct{}{}); err != nil {
			return fmt.Errorf("update Zabbix template item %s: %w", item.Name, err)
		}
	}
	return nil
}

func (c *Client) ensureChecks(ctx context.Context, plan Plan, hostIDs map[string]string) error {
	monitorID := hostIDs["lab-monitor-01"]
	if monitorID == "" {
		return errors.New("Zabbix monitor host was not reconciled")
	}
	for _, object := range plan.Objects {
		if object.Kind != "check" {
			continue
		}
		var existing []zabbixObject
		if err := c.call(ctx, "item.get", map[string]any{"output": []string{"itemid", "name", "key_"}, "selectTags": "extend", "hostids": []string{monitorID}, "filter": map[string]any{"key_": []string{object.Key}}}, &existing); err != nil {
			return fmt.Errorf("read Zabbix check %s: %w", object.Name, err)
		}
		payload := map[string]any{"hostid": monitorID, "name": object.Name, "key_": object.Key, "type": 3, "value_type": 3, "delay": "60s", "tags": apiTags()}
		if len(existing) == 0 {
			var created struct {
				IDs []string `json:"itemids"`
			}
			if err := c.call(ctx, "item.create", payload, &created); err != nil {
				return fmt.Errorf("create Zabbix check %s: %w", object.Name, err)
			}
			continue
		}
		if !zabbixOwned(existing[0].Tags) {
			return fmt.Errorf("refusing to update unowned Zabbix check %s", object.Name)
		}
		payload["itemid"] = existing[0].ItemID
		if err := c.call(ctx, "item.update", payload, &struct{}{}); err != nil {
			return fmt.Errorf("update Zabbix check %s: %w", object.Name, err)
		}
	}
	return nil
}

func (c *Client) ensureDashboards(ctx context.Context, plan Plan) error {
	for _, object := range plan.Objects {
		if object.Kind != "dashboard" {
			continue
		}
		var dashboards []zabbixObject
		if err := c.call(ctx, "dashboard.get", map[string]any{"output": []string{"dashboardid", "name"}, "selectPages": "extend", "filter": map[string]any{"name": []string{object.Name}}}, &dashboards); err != nil {
			return fmt.Errorf("read Zabbix dashboard %s: %w", object.Name, err)
		}
		payload := dashboardPayload(object.Name)
		if len(dashboards) == 0 {
			var created struct {
				IDs []string `json:"dashboardids"`
			}
			if err := c.call(ctx, "dashboard.create", payload, &created); err != nil {
				return fmt.Errorf("create Zabbix dashboard %s: %w", object.Name, err)
			}
			continue
		}
		if !strings.HasPrefix(dashboards[0].Name, "boetticher ") {
			return fmt.Errorf("refusing to update an unowned Zabbix dashboard %s", object.Name)
		}
		payload["dashboardid"] = dashboards[0].DashboardID
		if err := c.call(ctx, "dashboard.update", payload, &struct{}{}); err != nil {
			return fmt.Errorf("update Zabbix dashboard %s: %w", object.Name, err)
		}
	}
	return nil
}

func dashboardPayload(name string) map[string]any {
	return map[string]any{
		"name":           name,
		"private":        0,
		"display_period": 30,
		"auto_start":     0,
		"pages": []map[string]any{
			{
				"name": "Platform",
				"widgets": []map[string]any{
					{
						"type":      "problems",
						"name":      "boetticher platform problems",
						"x":         0,
						"y":         0,
						"width":     36,
						"height":    5,
						"view_mode": 0,
						"fields": []map[string]any{
							{"type": 1, "name": "tags.0.tag", "value": ownershipTag},
							{"type": 0, "name": "tags.0.operator", "value": 1},
							{"type": 1, "name": "tags.0.value", "value": "managed"},
						},
					},
				},
			},
		},
	}
}

func (c *Client) call(ctx context.Context, method string, params any, result any) error {
	id := c.nextID
	c.nextID++
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "auth": c.auth, "id": id})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api_jsonrpc.php", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Zabbix API HTTP %s", response.Status)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *APIError       `json:"error"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode Zabbix API response: %w", err)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if result != nil && len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return fmt.Errorf("decode Zabbix %s result: %w", method, err)
		}
	}
	return nil
}
