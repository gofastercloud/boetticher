package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/observability/incidents"
)

type runnerInvestigator struct {
	Python string
	Runner string
	Alias  string
}

func (i runnerInvestigator) Investigate(ctx context.Context, request incidents.InvestigationRequest) (incidents.InvestigationResult, error) {
	if strings.TrimSpace(i.Python) == "" || strings.TrimSpace(i.Runner) == "" {
		return incidents.InvestigationResult{State: incidents.Unavailable, Detail: "Holmes runner is not configured"}, nil
	}
	question := fmt.Sprintf("Investigate incident %s from %s: %s\nObserved detail: %s\nReturn observed evidence, likely cause, and safe next checks. Do not mutate anything.", request.Incident.ID, request.Incident.Source, request.Incident.Title, request.Incident.Body)
	command := exec.CommandContext(ctx, i.Python, i.Runner, "--model-alias", i.Alias)
	command.Stdin = strings.NewReader(question)
	out, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return incidents.InvestigationResult{State: incidents.Failed, Detail: "Holmes investigation deadline exceeded"}, ctx.Err()
		}
		return incidents.InvestigationResult{State: incidents.Failed, Detail: "Holmes runner failed"}, err
	}
	return incidents.InvestigationResult{State: incidents.Completed, Detail: string(out)}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8091", "loopback listen address")
	database := flag.String("database", "/var/lib/boetticher/observability/state/incidents/incidents.db", "incident SQLite path")
	tokenFile := flag.String("token-file", "/run/credentials/boetticher-incidentd.service/holmes-client-token", "local webhook/auth token")
	python := flag.String("python", "/opt/boetticher/observability/holmes/venv/bin/python", "Holmes Python executable")
	runner := flag.String("runner", "/opt/boetticher/observability/holmes/holmes-runner.py", "Holmes runner path")
	alias := flag.String("model-alias", "operations", "configured Holmes model alias")
	retentionDays := flag.Int("retention-days", 30, "incident retention in days")
	maxIncidents := flag.Int("max-incidents", 100, "maximum retained incidents")
	maxRounds := flag.Int("max-rounds", 6, "maximum investigation rounds")
	deadlineSeconds := flag.Int("deadline-seconds", 300, "investigation deadline")
	dailyBudget := flag.Float64("daily-budget-usd", 2, "conservative daily model budget")
	perInvestigationBudget := flag.Float64("investigation-budget-usd", 0.25, "conservative per-investigation model budget")
	flag.Parse()
	tokenBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		panic(err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		panic("incident webhook token is empty")
	}
	if err := os.MkdirAll(filepath.Dir(*database), 0o750); err != nil {
		panic(err)
	}
	store, err := incidents.Open(*database, incidents.Limits{Retention: time.Duration(*retentionDays) * 24 * time.Hour, MaxIncidents: *maxIncidents, MaxRounds: *maxRounds, MaxInvestigations: 1, InvestigationBudget: time.Duration(*deadlineSeconds) * time.Second, InvestigationDeadline: time.Duration(*deadlineSeconds) * time.Second, DailyBudgetUSD: *dailyBudget, InvestigationBudgetUSD: *perInvestigationBudget})
	if err != nil {
		panic(err)
	}
	defer store.Close()
	_, _ = store.Recover(context.Background())
	handler := incidents.Handler{
		Store:        store,
		WebhookToken: token,
		Authorize: func(r *http.Request) bool {
			return r.Header.Get("X-Grafana-User") != "" || r.Header.Get("X-Forwarded-User") != "" || strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) == token
		},
		Investigator: runnerInvestigator{Python: *python, Runner: *runner, Alias: *alias},
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
