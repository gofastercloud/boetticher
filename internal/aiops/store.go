package aiops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

type Status struct {
	States             map[State]int `json:"states"`
	Investigations24h  int           `json:"investigations_24h"`
	InputTokens24h     int           `json:"input_tokens_24h"`
	OutputTokens24h    int           `json:"output_tokens_24h"`
	PendingNoteWrites  int           `json:"pending_note_writes"`
	FailedNoteWrites   int           `json:"failed_note_writes"`
	OldestQueuedAt     string        `json:"oldest_queued_at,omitempty"`
	OldestQueuedAge    int64         `json:"oldest_queued_age_seconds,omitempty"`
	CurrentStartedAt   string        `json:"current_started_at,omitempty"`
	CurrentRunningAge  int64         `json:"current_investigation_age_seconds,omitempty"`
	LastTerminalState  State         `json:"last_terminal_state,omitempty"`
	LastTerminalResult Outcome       `json:"last_terminal_result,omitempty"`
	LastTerminalAt     string        `json:"last_terminal_at,omitempty"`
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
delivery_count INTEGER NOT NULL, missing_polls INTEGER NOT NULL DEFAULT 0, accepted_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
queued_at TEXT, started_at TEXT, completed_at TEXT, resolved_at TEXT,
final_report TEXT, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
holmes_steps INTEGER NOT NULL DEFAULT 0, evidence_calls INTEGER NOT NULL DEFAULT 0)`,
		`CREATE INDEX IF NOT EXISTS incidents_state_queue ON incidents(state,queued_at)`,
		`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, state TEXT NOT NULL, at TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', FOREIGN KEY(incident_id) REFERENCES incidents(id))`,
		`CREATE TABLE IF NOT EXISTS evidence_refs (incident_id TEXT NOT NULL, reference TEXT NOT NULL, source TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, collected_at TEXT NOT NULL, PRIMARY KEY(incident_id, reference), FOREIGN KEY(incident_id) REFERENCES incidents(id))`,
		`CREATE TABLE IF NOT EXISTS note_deliveries (incident_id TEXT NOT NULL, transition TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', PRIMARY KEY(incident_id, transition), FOREIGN KEY(incident_id) REFERENCES incidents(id))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize AIOps database: %w", err)
		}
	}
	return &Store{db: db, path: path}, nil
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
	var oldest, running, terminalState, terminalAt sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT min(queued_at) FROM incidents WHERE state='queued'`).Scan(&oldest); err != nil {
		return result, err
	}
	if oldest.Valid {
		result.OldestQueuedAt = oldest.String
		if accepted, parseErr := time.Parse(time.RFC3339Nano, oldest.String); parseErr == nil && now.After(accepted) {
			result.OldestQueuedAge = int64(now.Sub(accepted).Seconds())
		}
	}
	if err := s.db.QueryRowContext(ctx, `SELECT min(started_at) FROM incidents WHERE state='running'`).Scan(&running); err != nil {
		return result, err
	}
	if running.Valid {
		result.CurrentStartedAt = running.String
		if started, parseErr := time.Parse(time.RFC3339Nano, running.String); parseErr == nil && now.After(started) {
			result.CurrentRunningAge = int64(now.Sub(started).Seconds())
		}
	}
	var terminalResult sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT state,outcome,coalesce(resolved_at,completed_at) FROM incidents WHERE state IN ('completed','inconclusive','failed','resolved') ORDER BY coalesce(resolved_at,completed_at) DESC LIMIT 1`).Scan(&terminalState, &terminalResult, &terminalAt); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("read latest terminal investigation: %w", err)
	}
	if terminalState.Valid {
		result.LastTerminalState = State(terminalState.String)
		result.LastTerminalResult = Outcome(terminalResult.String)
		result.LastTerminalAt = terminalAt.String
	}
	return result, nil
}

func (s *Store) Admit(ctx context.Context, alert Alert, now time.Time) (Incident, bool, error) {
	if err := alert.Validate(); err != nil {
		return Incident{}, false, err
	}
	if err := s.checkCapacity(); err != nil {
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO note_deliveries(incident_id,transition,status) VALUES(?,?, 'pending')`, id, state); err != nil {
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
	var queued sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT id,fingerprint,pulse_alert_id,resource_id,kind,severity,title,state,outcome,defer_reason,delivery_count,accepted_at,last_seen_at,queued_at FROM incidents WHERE fingerprint=?`, fingerprint).Scan(&i.ID, &i.Fingerprint, &i.PulseAlertID, &i.ResourceID, &i.Kind, &i.Severity, &i.Title, &i.State, &i.Outcome, &i.DeferReason, &i.DeliveryCount, &accepted, &seen, &queued)
	if err == sql.ErrNoRows {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, err
	}
	i.AcceptedAt, _ = time.Parse(time.RFC3339Nano, accepted)
	i.LastSeenAt, _ = time.Parse(time.RFC3339Nano, seen)
	if queued.Valid {
		i.QueuedAt, _ = time.Parse(time.RFC3339Nano, queued.String)
	}
	return i, true, nil
}

func (s *Store) ClaimNext(ctx context.Context, now time.Time) (Incident, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, false, err
	}
	defer tx.Rollback()
	var running int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE state='running'`).Scan(&running); err != nil || running != 0 {
		return Incident{}, false, err
	}
	for _, budget := range []struct {
		window time.Duration
		limit  int
		reason string
	}{{time.Hour, MaxInvestigationsHour, "rate_hour"}, {24 * time.Hour, MaxInvestigationsDay, "rate_day"}} {
		var starts int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE started_at>=?`, timestamp(now.Add(-budget.window))).Scan(&starts); err != nil {
			return Incident{}, false, err
		}
		if starts >= budget.limit {
			var id string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM incidents WHERE state='queued' ORDER BY queued_at,id LIMIT 1`).Scan(&id); err == sql.ErrNoRows {
				return Incident{}, false, nil
			} else if err != nil {
				return Incident{}, false, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE incidents SET state='deferred',defer_reason=? WHERE id=?`, budget.reason, id); err != nil {
				return Incident{}, false, err
			}
			if err := recordTransition(ctx, tx, id, StateDeferred, now, budget.reason); err != nil {
				return Incident{}, false, err
			}
			return Incident{}, false, tx.Commit()
		}
	}
	var incident Incident
	var accepted, seen, queued string
	err = tx.QueryRowContext(ctx, `SELECT id,fingerprint,pulse_alert_id,resource_id,kind,severity,title,state,outcome,defer_reason,delivery_count,accepted_at,last_seen_at,queued_at FROM incidents WHERE state='queued' ORDER BY queued_at,id LIMIT 1`).Scan(&incident.ID, &incident.Fingerprint, &incident.PulseAlertID, &incident.ResourceID, &incident.Kind, &incident.Severity, &incident.Title, &incident.State, &incident.Outcome, &incident.DeferReason, &incident.DeliveryCount, &accepted, &seen, &queued)
	if err == sql.ErrNoRows {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, err
	}
	incident.AcceptedAt, _ = time.Parse(time.RFC3339Nano, accepted)
	incident.LastSeenAt, _ = time.Parse(time.RFC3339Nano, seen)
	incident.QueuedAt, _ = time.Parse(time.RFC3339Nano, queued)
	incident.StartedAt = now.UTC()
	incident.State = StateRunning
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET state='running',started_at=?,defer_reason='' WHERE id=? AND state='queued'`, timestamp(now), incident.ID)
	if err != nil {
		return Incident{}, false, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Incident{}, false, errors.New("queued incident claim lost")
	}
	if err := recordTransition(ctx, tx, incident.ID, StateRunning, now, ""); err != nil {
		return Incident{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Incident{}, false, err
	}
	return incident, true, nil
}

func (s *Store) PromoteDeferred(ctx context.Context, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE state IN ('queued','running')`).Scan(&active); err != nil || active >= MaxQueue {
		return false, err
	}
	for _, budget := range []struct {
		window time.Duration
		limit  int
	}{{time.Hour, MaxInvestigationsHour}, {24 * time.Hour, MaxInvestigationsDay}} {
		var starts int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE started_at>=?`, timestamp(now.Add(-budget.window))).Scan(&starts); err != nil || starts >= budget.limit {
			return false, err
		}
	}
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM incidents WHERE state='deferred' ORDER BY accepted_at,id LIMIT 1`).Scan(&id); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE incidents SET state='queued',queued_at=?,defer_reason='' WHERE id=?`, timestamp(now), id); err != nil {
		return false, err
	}
	if err := recordTransition(ctx, tx, id, StateQueued, now, "promoted"); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) Reconcile(ctx context.Context, alerts []Alert, now time.Time) ([]string, error) {
	present := make(map[string]bool, len(alerts))
	for _, alert := range alerts {
		incident, _, err := s.Admit(ctx, alert, now)
		if err != nil {
			return nil, err
		}
		present[incident.Fingerprint] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,fingerprint,missing_polls,last_seen_at FROM incidents WHERE state NOT IN ('resolved')`)
	if err != nil {
		return nil, err
	}
	type missingIncident struct {
		id, fingerprint, lastSeen string
		missing                   int
	}
	var incidents []missingIncident
	var resolved []string
	for rows.Next() {
		var incident missingIncident
		if err := rows.Scan(&incident.id, &incident.fingerprint, &incident.missing, &incident.lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		incidents = append(incidents, incident)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, incident := range incidents {
		if present[incident.fingerprint] {
			if _, err := tx.ExecContext(ctx, `UPDATE incidents SET missing_polls=0 WHERE id=?`, incident.id); err != nil {
				return nil, err
			}
			continue
		}
		incident.missing++
		lastSeen, _ := time.Parse(time.RFC3339Nano, incident.lastSeen)
		if incident.missing >= 3 && now.Sub(lastSeen) >= 3*time.Minute {
			if _, err := tx.ExecContext(ctx, `UPDATE incidents SET state='resolved',resolved_at=?,missing_polls=? WHERE id=?`, timestamp(now), incident.missing, incident.id); err != nil {
				return nil, err
			}
			if err := recordTransition(ctx, tx, incident.id, StateResolved, now, "absent_three_polls"); err != nil {
				return nil, err
			}
			resolved = append(resolved, incident.id)
		} else if _, err := tx.ExecContext(ctx, `UPDATE incidents SET missing_polls=? WHERE id=?`, incident.missing, incident.id); err != nil {
			return nil, err
		}
	}
	return resolved, tx.Commit()
}

type PendingNote struct {
	IncidentID   string
	PulseAlertID string
	Transition   State
	Text         string
}

func (s *Store) NextPendingNote(ctx context.Context) (PendingNote, bool, error) {
	var note PendingNote
	var report []byte
	err := s.db.QueryRowContext(ctx, `SELECT n.incident_id,i.pulse_alert_id,n.transition,coalesce(i.final_report,'') FROM note_deliveries n JOIN incidents i ON i.id=n.incident_id WHERE n.status='pending' ORDER BY n.rowid LIMIT 1`).Scan(&note.IncidentID, &note.PulseAlertID, &note.Transition, &report)
	if err == sql.ErrNoRows {
		return PendingNote{}, false, nil
	}
	if err != nil {
		return PendingNote{}, false, err
	}
	note.Text = "Boetticher AIOps: " + string(note.Transition)
	if (note.Transition == StateCompleted || note.Transition == StateInconclusive) && len(report) > 0 {
		var parsed Report
		if json.Unmarshal(report, &parsed) == nil {
			note.Text += "\n" + parsed.Summary
			if parsed.LikelyCause != "" {
				note.Text += "\nLikely cause: " + parsed.LikelyCause
			}
		}
	}
	return note, true, nil
}

func (s *Store) RecordNoteAttempt(ctx context.Context, note PendingNote, delivered bool, errorCode string) error {
	if !delivered && !safeToken(errorCode) {
		return errors.New("note failure requires a bounded code")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE note_deliveries SET attempts=attempts+1,status=CASE WHEN ? THEN 'sent' WHEN attempts>=4 THEN 'failed' ELSE 'pending' END,last_error=? WHERE incident_id=? AND transition=?`, delivered, errorCode, note.IncidentID, note.Transition)
	return err
}

func (s *Store) Complete(ctx context.Context, incidentID string, report Report, usage Usage, references []EvidenceReference, now time.Time) error {
	issued := make(map[string]bool, len(references))
	for _, reference := range references {
		issued[reference.Reference] = true
	}
	if err := report.Validate(issued); err != nil {
		return err
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.OutputTokens > MaxOutputTokens || usage.HolmesSteps < 0 || usage.HolmesSteps > MaxHolmesSteps || len(references) > MaxEvidenceCalls {
		return errors.New("investigation usage exceeded its safety budget")
	}
	serialized, err := json.Marshal(report)
	if err != nil || len(serialized) > 12*1024 {
		return errors.New("final report exceeded its serialized bound")
	}
	state := StateCompleted
	if report.Outcome == OutcomeInconclusive {
		state = StateInconclusive
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET state=?,outcome=?,completed_at=?,final_report=?,input_tokens=?,output_tokens=?,holmes_steps=?,evidence_calls=? WHERE id=? AND state='running'`, state, report.Outcome, timestamp(now), serialized, usage.InputTokens, usage.OutputTokens, usage.HolmesSteps, len(references), incidentID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("incident is not running")
	}
	for _, reference := range references {
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_refs(incident_id,reference,source,sha256,bytes,collected_at) VALUES(?,?,?,?,?,?)`, incidentID, reference.Reference, reference.Source, reference.SHA256, reference.Bytes, timestamp(reference.CollectedAt)); err != nil {
			return err
		}
	}
	if err := recordTransition(ctx, tx, incidentID, state, now, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Fail(ctx context.Context, incidentID, reason string, now time.Time) error {
	if !safeToken(reason) {
		return errors.New("failure reason must be a bounded code")
	}
	return s.transitionRunning(ctx, incidentID, StateFailed, reason, now)
}

func (s *Store) Resolve(ctx context.Context, incidentID, reason string, now time.Time) error {
	if !safeToken(reason) {
		return errors.New("resolution reason must be a bounded code")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET state='resolved',resolved_at=? WHERE id=? AND state!='resolved'`, timestamp(now), incidentID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		var state State
		if err := tx.QueryRowContext(ctx, `SELECT state FROM incidents WHERE id=?`, incidentID).Scan(&state); err == nil && state == StateResolved {
			return nil
		}
		return errors.New("incident is absent")
	}
	if err := recordTransition(ctx, tx, incidentID, StateResolved, now, reason); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) IncidentState(ctx context.Context, incidentID string) (State, error) {
	var state State
	err := s.db.QueryRowContext(ctx, `SELECT state FROM incidents WHERE id=?`, incidentID).Scan(&state)
	return state, err
}

func (s *Store) transitionRunning(ctx context.Context, incidentID string, state State, detail string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET state=?,completed_at=? WHERE id=? AND state='running'`, state, timestamp(now), incidentID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("incident is not running")
	}
	if err := recordTransition(ctx, tx, incidentID, state, now, detail); err != nil {
		return err
	}
	return tx.Commit()
}

func recordTransition(ctx context.Context, tx *sql.Tx, incidentID string, state State, now time.Time, detail string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(incident_id,state,at,detail) VALUES(?,?,?,?)`, incidentID, state, timestamp(now), detail); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO note_deliveries(incident_id,transition,status) VALUES(?,?,'pending') ON CONFLICT(incident_id,transition) DO NOTHING`, incidentID, state)
	return err
}

func (s *Store) Prune(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	cutoff := timestamp(now.Add(-Retention))
	for _, table := range []string{"note_deliveries", "evidence_refs", "audit"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE incident_id IN (SELECT id FROM incidents WHERE state='resolved' AND resolved_at<?)`, cutoff); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM incidents WHERE state='resolved' AND resolved_at<?`, cutoff); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

func (s *Store) checkCapacity() error {
	var size int64
	for _, path := range []string{s.path, s.path + "-wal"} {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect AIOps database capacity: %w", err)
		}
		size += info.Size()
	}
	if size > MaxDatabaseBytes {
		return errors.New("AIOps database exceeds its 256 MiB cap")
	}
	return nil
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func nullableTimestamp(ok bool, t time.Time) any {
	if !ok {
		return nil
	}
	return timestamp(t)
}
