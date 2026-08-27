package aiops

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type Status struct {
	States            map[State]int `json:"states"`
	Investigations24h int           `json:"investigations_24h"`
	InputTokens24h    int           `json:"input_tokens_24h"`
	OutputTokens24h   int           `json:"output_tokens_24h"`
	PendingNoteWrites int           `json:"pending_note_writes"`
	FailedNoteWrites  int           `json:"failed_note_writes"`
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("AIOps database path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS incidents (
id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, pulse_alert_id TEXT NOT NULL,
resource_id TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
state TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT '', defer_reason TEXT NOT NULL DEFAULT '',
delivery_count INTEGER NOT NULL, accepted_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
queued_at TEXT, started_at TEXT, completed_at TEXT, resolved_at TEXT,
final_report TEXT, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
holmes_steps INTEGER NOT NULL DEFAULT 0, evidence_calls INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, state TEXT NOT NULL, at TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', FOREIGN KEY(incident_id) REFERENCES incidents(id))`,
		`CREATE TABLE IF NOT EXISTS evidence_refs (incident_id TEXT NOT NULL, reference TEXT NOT NULL, source TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, collected_at TEXT NOT NULL, PRIMARY KEY(incident_id, reference), FOREIGN KEY(incident_id) REFERENCES incidents(id))`,
		`CREATE TABLE IF NOT EXISTS note_deliveries (incident_id TEXT NOT NULL, transition TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', PRIMARY KEY(incident_id, transition), FOREIGN KEY(incident_id) REFERENCES incidents(id))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize AIOps database: %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Status(ctx context.Context, now time.Time) (Status, error) {
	result := Status{States: map[State]int{}}
	rows, err := s.db.QueryContext(ctx, `SELECT state,count(*) FROM incidents GROUP BY state`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var state State
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return result, err
		}
		result.States[state] = count
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(input_tokens),0),coalesce(sum(output_tokens),0) FROM incidents WHERE started_at>=?`, timestamp(now.Add(-24*time.Hour))).Scan(&result.Investigations24h, &result.InputTokens24h, &result.OutputTokens24h); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM note_deliveries WHERE status='pending'`).Scan(&result.PendingNoteWrites); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM note_deliveries WHERE status='failed'`).Scan(&result.FailedNoteWrites); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) Admit(ctx context.Context, alert Alert, now time.Time) (Incident, bool, error) {
	if err := alert.Validate(); err != nil {
		return Incident{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, false, err
	}
	defer tx.Rollback()
	fingerprint := alert.Fingerprint()
	if incident, ok, err := loadByFingerprint(ctx, tx, fingerprint); err != nil {
		return Incident{}, false, err
	} else if ok {
		incident.DeliveryCount++
		incident.LastSeenAt = now.UTC()
		if _, err := tx.ExecContext(ctx, `UPDATE incidents SET delivery_count=?, last_seen_at=? WHERE id=?`, incident.DeliveryCount, timestamp(incident.LastSeenAt), incident.ID); err != nil {
			return Incident{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Incident{}, false, err
		}
		return incident, true, nil
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE state IN ('queued','running')`).Scan(&active); err != nil {
		return Incident{}, false, err
	}
	state, reason := StateQueued, ""
	if active >= MaxQueue {
		state, reason = StateDeferred, "queue_full"
	}
	id := fingerprint[:32]
	incident := Incident{ID: id, Fingerprint: fingerprint, PulseAlertID: alert.PulseAlertID, ResourceID: alert.ResourceID, State: state, DeferReason: reason, DeliveryCount: 1, AcceptedAt: now.UTC(), LastSeenAt: now.UTC()}
	_, err = tx.ExecContext(ctx, `INSERT INTO incidents(id,fingerprint,pulse_alert_id,resource_id,kind,severity,title,state,defer_reason,delivery_count,accepted_at,last_seen_at,queued_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, fingerprint, alert.PulseAlertID, alert.ResourceID, alert.Kind, alert.Severity, alert.Title, state, reason, 1, timestamp(now), timestamp(now), nullableTimestamp(state == StateQueued, now))
	if err != nil {
		return Incident{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(incident_id,state,at,detail) VALUES(?,?,?,?)`, id, state, timestamp(now), reason); err != nil {
		return Incident{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Incident{}, false, err
	}
	return incident, false, nil
}

func loadByFingerprint(ctx context.Context, tx *sql.Tx, fingerprint string) (Incident, bool, error) {
	var i Incident
	var accepted, seen string
	err := tx.QueryRowContext(ctx, `SELECT id,fingerprint,pulse_alert_id,resource_id,state,outcome,defer_reason,delivery_count,accepted_at,last_seen_at FROM incidents WHERE fingerprint=?`, fingerprint).Scan(&i.ID, &i.Fingerprint, &i.PulseAlertID, &i.ResourceID, &i.State, &i.Outcome, &i.DeferReason, &i.DeliveryCount, &accepted, &seen)
	if err == sql.ErrNoRows {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, err
	}
	i.AcceptedAt, _ = time.Parse(time.RFC3339Nano, accepted)
	i.LastSeenAt, _ = time.Parse(time.RFC3339Nano, seen)
	return i, true, nil
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func nullableTimestamp(ok bool, t time.Time) any {
	if !ok {
		return nil
	}
	return timestamp(t)
}
