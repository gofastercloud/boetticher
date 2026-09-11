// Package incidents contains the bounded, durable Holmes incident queue.
// It deliberately has no monitoring or alerting side effects: callers provide
// alerts and an explicitly read-only investigator performs investigation.
package incidents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type State string

const (
	Queued        State = "queued"
	Investigating State = "investigating"
	Completed     State = "completed"
	Failed        State = "failed"
	Unavailable   State = "unavailable"
	Recovery      State = "recovery"
)

type Limits struct {
	Retention              time.Duration
	MaxIncidents           int
	MaxRounds              int
	MaxInvestigations      int
	InvestigationBudget    time.Duration
	InvestigationDeadline  time.Duration
	DailyBudgetUSD         float64
	InvestigationBudgetUSD float64
}

func (l Limits) normalized() Limits {
	if l.Retention <= 0 {
		l.Retention = 30 * 24 * time.Hour
	}
	if l.MaxIncidents <= 0 {
		l.MaxIncidents = 1000
	}
	if l.MaxRounds <= 0 {
		l.MaxRounds = 6
	}
	if l.MaxInvestigations <= 0 {
		l.MaxInvestigations = 1
	}
	if l.InvestigationBudget <= 0 {
		l.InvestigationBudget = 5 * time.Minute
	}
	if l.InvestigationDeadline <= 0 {
		l.InvestigationDeadline = 30 * time.Second
	}
	return l
}

type Alert struct {
	ID          string            `json:"id,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Source      string            `json:"source"`
	Title       string            `json:"title"`
	Body        string            `json:"body,omitempty"`
	Group       string            `json:"group,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	ObservedAt  time.Time         `json:"observed_at"`
}

const (
	maxAlertID        = 128
	maxAlertText      = 4096
	maxAlertLabels    = 32
	maxAlertLabelText = 128
)

type Incident struct {
	ID          string
	Fingerprint string
	Group       string
	Source      string
	Title       string
	Body        string
	Labels      map[string]string
	State       State
	Attempts    int
	Rounds      int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastError   string
}

type Store struct {
	db     *sql.DB
	limits Limits
	now    func() time.Time
}

func Open(path string, limits Limits) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("incident store path is empty")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, limits: limits.normalized(), now: time.Now}
	if err = s.init(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// NewStore is useful for tests and callers that already own a SQLite handle.
func NewStore(db *sql.DB, limits Limits) (*Store, error) {
	if db == nil {
		return nil, errors.New("incident database is nil")
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, limits: limits.normalized(), now: time.Now}
	if err := s.init(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS incidents (
 id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, grp TEXT NOT NULL, source TEXT NOT NULL,
 title TEXT NOT NULL, body TEXT NOT NULL, labels_json TEXT NOT NULL, state TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, rounds INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_active_fingerprint ON incidents(fingerprint)
 WHERE state IN ('queued','investigating','unavailable','recovery');
CREATE INDEX IF NOT EXISTS incidents_updated ON incidents(updated_at);
CREATE TABLE IF NOT EXISTS incident_events (
 event_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, state TEXT NOT NULL,
 created_at INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS incident_budget (
 day TEXT PRIMARY KEY, reserved_cents INTEGER NOT NULL DEFAULT 0
);`)
	return err
}

func fingerprint(a Alert) string {
	if strings.TrimSpace(a.Fingerprint) != "" {
		return strings.TrimSpace(a.Fingerprint)
	}
	labels := make([]string, 0, len(a.Labels))
	for k, v := range a.Labels {
		labels = append(labels, k+"="+v)
	}
	sort.Strings(labels)
	h := sha256.Sum256([]byte(a.Source + "\x00" + a.Title + "\x00" + a.Group + "\x00" + strings.Join(labels, "\x00")))
	return hex.EncodeToString(h[:])
}

func (s *Store) Intake(ctx context.Context, a Alert) (Incident, bool, error) {
	if strings.TrimSpace(a.Source) == "" || strings.TrimSpace(a.Title) == "" {
		return Incident{}, false, errors.New("alert source and title are required")
	}
	if len(a.ID) > maxAlertID || len(a.Fingerprint) > maxAlertID || len(a.Source) > maxAlertLabelText || len(a.Title) > maxAlertText || len(a.Body) > maxAlertText || len(a.Group) > maxAlertLabelText {
		return Incident{}, false, errors.New("alert exceeds its size bound")
	}
	if len(a.Labels) > maxAlertLabels {
		return Incident{}, false, errors.New("alert has too many labels")
	}
	for key, value := range a.Labels {
		if len(key) == 0 || len(key) > maxAlertLabelText || len(value) > maxAlertLabelText {
			return Incident{}, false, errors.New("alert label exceeds its size bound")
		}
	}
	if a.ObservedAt.IsZero() {
		a.ObservedAt = s.now()
	}
	if a.Group == "" {
		a.Group = a.Source
	}
	fp := fingerprint(a)
	if existing, err := s.getActiveByFingerprint(ctx, fp); err == nil {
		return existing, true, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Incident{}, false, err
	}
	var active int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE state IN ('queued','investigating','unavailable','recovery')`).Scan(&active); err != nil {
		return Incident{}, false, err
	}
	if active >= s.limits.MaxIncidents {
		return Incident{}, false, errors.New("incident queue is full")
	}
	labels, _ := json.Marshal(a.Labels)
	now := s.now().UnixNano()
	id := strings.TrimSpace(a.ID)
	if id == "" {
		id = fmt.Sprintf("%s-%d", fp, now)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO incidents(id,fingerprint,grp,source,title,body,labels_json,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, fp, a.Group, a.Source, a.Title, a.Body, labels, Queued, a.ObservedAt.UnixNano(), now)
	if err == nil {
		_ = s.prune(ctx)
		i, _, getErr := s.Get(ctx, id, false)
		return i, false, getErr
	}
	if a.ID != "" {
		if existing, found, getErr := s.Get(ctx, a.ID, true); getErr == nil && found {
			if existing.Fingerprint != fp {
				return Incident{}, false, errors.New("alert id is already used by another fingerprint")
			}
			return existing, true, nil
		}
	}
	return Incident{}, false, err
}

func (s *Store) getActiveByFingerprint(ctx context.Context, fp string) (Incident, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,fingerprint,grp,source,title,body,labels_json,state,attempts,rounds,created_at,updated_at,last_error FROM incidents WHERE fingerprint=? AND state IN ('queued','investigating','unavailable','recovery') ORDER BY updated_at DESC LIMIT 1`, fp)
	return scan(row)
}

func (s *Store) Get(ctx context.Context, id string, includeTerminal bool) (Incident, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,fingerprint,grp,source,title,body,labels_json,state,attempts,rounds,created_at,updated_at,last_error FROM incidents WHERE id=?`, id)
	i, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, err
	}
	if !includeTerminal && (i.State == Completed || i.State == Failed) {
		return i, false, nil
	}
	return i, true, nil
}

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Incident, error) {
	var i Incident
	var labels, state string
	var created, updated int64
	err := row.Scan(&i.ID, &i.Fingerprint, &i.Group, &i.Source, &i.Title, &i.Body, &labels, &state, &i.Attempts, &i.Rounds, &created, &updated, &i.LastError)
	if err != nil {
		return i, err
	}
	_ = json.Unmarshal([]byte(labels), &i.Labels)
	i.State = State(state)
	i.CreatedAt = time.Unix(0, created)
	i.UpdatedAt = time.Unix(0, updated)
	return i, nil
}

var transitions = map[State]map[State]bool{
	Queued:        {Investigating: true, Unavailable: true, Recovery: true, Failed: true},
	Investigating: {Completed: true, Failed: true, Unavailable: true, Recovery: true, Queued: true},
	Unavailable:   {Queued: true, Recovery: true, Failed: true},
	Recovery:      {Queued: true, Investigating: true, Completed: true, Failed: true, Unavailable: true},
}

func (s *Store) Transition(ctx context.Context, id string, from, to State, detail string) error {
	if !transitions[from][to] {
		return fmt.Errorf("invalid incident transition %s -> %s", from, to)
	}
	if to == Investigating {
		if _, err := s.db.ExecContext(ctx, `UPDATE incidents SET state=?,attempts=attempts+1,rounds=rounds+1,updated_at=? WHERE id=? AND state=? AND attempts<? AND rounds<?`, to, s.now().UnixNano(), id, from, s.limits.MaxInvestigations, s.limits.MaxRounds); err != nil {
			return err
		}
	} else if _, err := s.db.ExecContext(ctx, `UPDATE incidents SET state=?,last_error=?,updated_at=? WHERE id=? AND state=?`, to, detail, s.now().UnixNano(), id, from); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT changes()`).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return errors.New("incident transition was stale or out of order")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO incident_events(event_id,incident_id,state,created_at,detail) VALUES(?,?,?,?,?)`, fmt.Sprintf("%s-%d", id, s.now().UnixNano()), id, to, s.now().UnixNano(), detail)
	return err
}

// Recover resets in-flight work after a process restart. It never revives a
// terminal result and is safe to call repeatedly.
func (s *Store) Recover(ctx context.Context) (int, error) {
	r, err := s.db.ExecContext(ctx, `UPDATE incidents SET state='recovery',updated_at=? WHERE state='investigating'`, s.now().UnixNano())
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return int(n), nil
}

func (s *Store) List(ctx context.Context, states ...State) ([]Incident, error) {
	q := `SELECT id,fingerprint,grp,source,title,body,labels_json,state,attempts,rounds,created_at,updated_at,last_error FROM incidents`
	args := []any{}
	if len(states) > 0 {
		parts := make([]string, len(states))
		for i, v := range states {
			parts[i] = "?"
			args = append(args, v)
		}
		q += " WHERE state IN (" + strings.Join(parts, ",") + ")"
	}
	q += " ORDER BY updated_at ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Incident
	for rows.Next() {
		i, e := scan(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, i)
	}
	return result, rows.Err()
}

func (s *Store) prune(ctx context.Context) error {
	cutoff := s.now().Add(-s.limits.Retention).UnixNano()
	_, err := s.db.ExecContext(ctx, `DELETE FROM incidents WHERE updated_at<? AND state IN ('completed','failed')`, cutoff)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM incidents WHERE id IN (SELECT id FROM incidents WHERE state IN ('completed','failed') ORDER BY updated_at DESC LIMIT -1 OFFSET ?)`, s.limits.MaxIncidents)
	return err
}

type InvestigationRequest struct {
	Incident         Incident
	Round            int
	Budget, Deadline time.Duration
}
type InvestigationResult struct {
	State  State
	Detail string
}

// Investigator is read-only by contract: implementations may query evidence,
// but must not mutate monitored systems or configuration.
type Investigator interface {
	Investigate(context.Context, InvestigationRequest) (InvestigationResult, error)
}

func (s *Store) Investigate(ctx context.Context, id string, inv Investigator) (Incident, error) {
	if inv == nil {
		return Incident{}, errors.New("investigator is nil")
	}
	i, ok, err := s.Get(ctx, id, true)
	if err != nil {
		return i, err
	}
	if !ok {
		return i, sql.ErrNoRows
	}
	if i.State != Queued && i.State != Recovery && i.State != Unavailable {
		return i, fmt.Errorf("incident %s is not ready: %s", id, i.State)
	}
	if err = s.reserveBudget(ctx); err != nil {
		return i, err
	}
	if err = s.Transition(ctx, id, i.State, Investigating, ""); err != nil {
		return i, err
	}
	i, _, _ = s.Get(ctx, id, true)
	budget := s.limits.InvestigationBudget
	deadline := s.limits.InvestigationDeadline
	if deadline > budget {
		deadline = budget
	}
	budget = deadline
	callCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	result, callErr := inv.Investigate(callCtx, InvestigationRequest{Incident: i, Round: i.Rounds, Budget: budget, Deadline: deadline})
	if callErr != nil {
		_ = s.Transition(ctx, id, Investigating, Failed, callErr.Error())
	} else {
		target := result.State
		if target == "" {
			target = Completed
		}
		if target != Completed && target != Unavailable && target != Failed && target != Recovery {
			target = Failed
		}
		_ = s.Transition(ctx, id, Investigating, target, result.Detail)
	}
	final, _, _ := s.Get(ctx, id, true)
	return final, callErr
}

// reserveBudget conservatively reserves the maximum approved per-investigation
// amount before invoking the model. Unknown provider usage never allows a
// call beyond the configured daily budget.
func (s *Store) reserveBudget(ctx context.Context) error {
	if s.limits.DailyBudgetUSD <= 0 || s.limits.InvestigationBudgetUSD <= 0 {
		return nil
	}
	day := s.now().UTC().Format("2006-01-02")
	maxCents := int64(s.limits.DailyBudgetUSD * 100)
	reserveCents := int64(s.limits.InvestigationBudgetUSD * 100)
	if reserveCents < 1 {
		reserveCents = 1
	}
	for {
		var reserved int64
		err := s.db.QueryRowContext(ctx, `SELECT reserved_cents FROM incident_budget WHERE day=?`, day).Scan(&reserved)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = s.db.ExecContext(ctx, `INSERT INTO incident_budget(day,reserved_cents) VALUES(?,?)`, day, reserveCents)
			if err == nil {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		if reserved+reserveCents > maxCents {
			return errors.New("Holmes daily investigation budget is exhausted")
		}
		result, err := s.db.ExecContext(ctx, `UPDATE incident_budget SET reserved_cents=? WHERE day=? AND reserved_cents=?`, reserved+reserveCents, day, reserved)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed == 1 {
			return nil
		}
	}
}
