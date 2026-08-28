package firewalltelemetry

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewall"
	_ "modernc.org/sqlite"
)

const (
	DefaultRawRetention = time.Duration(firewall.TelemetryRawRetentionDays) * 24 * time.Hour
	SampleStaleAfter    = 45 * time.Second
	EventRetention      = 30 * 24 * time.Hour
	MaxRuleResults      = 256
	MaxActivityResults  = 256
	MaxEventResults     = 200
	MaxSecurityResults  = 32
)

type Store struct {
	db        *sql.DB
	retention time.Duration
}

func OpenStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("telemetry database path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create telemetry state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open telemetry database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, retention: DefaultRawRetention}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) initialize() error {
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		`CREATE TABLE IF NOT EXISTS rules (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			comment TEXT NOT NULL UNIQUE,
			family TEXT NOT NULL,
			table_name TEXT NOT NULL,
			chain_name TEXT NOT NULL,
			first_seen_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL,
			last_packets TEXT NOT NULL,
			last_bytes TEXT NOT NULL,
			last_packet_delta TEXT NOT NULL,
			last_byte_delta TEXT NOT NULL,
			last_reset INTEGER NOT NULL DEFAULT 0,
			epoch INTEGER NOT NULL DEFAULT 0,
			last_sample_at INTEGER NOT NULL,
			active INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id TEXT NOT NULL REFERENCES rules(id),
			sampled_at INTEGER NOT NULL,
			packets TEXT NOT NULL,
			bytes TEXT NOT NULL,
			packet_delta TEXT NOT NULL,
			byte_delta TEXT NOT NULL,
			epoch INTEGER NOT NULL,
			reset INTEGER NOT NULL DEFAULT 0
		)`,
		"CREATE INDEX IF NOT EXISTS samples_rule_time ON samples(rule_id, sampled_at)",
		"CREATE INDEX IF NOT EXISTS samples_time ON samples(sampled_at)",
		`CREATE TABLE IF NOT EXISTS epochs (
			rule_id TEXT NOT NULL REFERENCES rules(id),
			epoch INTEGER NOT NULL,
			started_at INTEGER NOT NULL,
			reason TEXT NOT NULL,
			previous_packets TEXT NOT NULL,
			previous_bytes TEXT NOT NULL,
			PRIMARY KEY(rule_id, epoch)
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			observed_at INTEGER NOT NULL,
			kind TEXT NOT NULL,
			rule_id TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL DEFAULT '',
			previous_fingerprint TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT ''
		)`,
		"CREATE INDEX IF NOT EXISTS events_time ON events(observed_at)",
		`CREATE TABLE IF NOT EXISTS health (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("initialize telemetry database: %w", err)
		}
	}
	rows, err := s.db.Query(`PRAGMA table_info(rules)`)
	if err != nil {
		return fmt.Errorf("inspect telemetry rules schema: %w", err)
	}
	activeColumn := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan telemetry rules schema: %w", err)
		}
		if name == "active" {
			activeColumn = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("read telemetry rules schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close telemetry rules schema: %w", err)
	}
	if !activeColumn {
		if _, err := s.db.Exec(`ALTER TABLE rules ADD COLUMN active INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("migrate telemetry rules schema: %w", err)
		}
	}
	return nil
}

func (s *Store) RecordSnapshot(at time.Time, snapshot firewall.NFTSnapshot) error {
	at = at.UTC()
	if at.IsZero() || snapshot.Fingerprint == "" {
		return errors.New("telemetry snapshot requires a timestamp and fingerprint")
	}
	seen := make(map[string]struct{}, len(snapshot.Counters))
	for _, counter := range snapshot.Counters {
		if _, exists := seen[counter.ID]; exists {
			return fmt.Errorf("telemetry snapshot contains duplicate rule id %q", counter.ID)
		}
		seen[counter.ID] = struct{}{}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin telemetry sample transaction: %w", err)
	}
	rollback := func(err error) error {
		_ = tx.Rollback()
		return err
	}
	now := at.UnixNano()
	previousFingerprint, _ := s.healthTx(tx, "last_fingerprint")
	if previousFingerprint != "" && previousFingerprint != snapshot.Fingerprint {
		if _, err := tx.Exec(`INSERT INTO events (observed_at, kind, fingerprint, previous_fingerprint, detail) VALUES (?, 'ruleset_change', ?, ?, ?)`, now, snapshot.Fingerprint, previousFingerprint, fmt.Sprintf("owned objects changed: %d", snapshot.OwnedObjectCount)); err != nil {
			return rollback(fmt.Errorf("record ruleset change: %w", err))
		}
		if err := s.setHealthTx(tx, "last_structural_change_at", strconv.FormatInt(now, 10)); err != nil {
			return rollback(err)
		}
	}
	for _, counter := range snapshot.Counters {
		previous, err := s.previousRuleTx(tx, counter.ID)
		if err != nil {
			return rollback(err)
		}
		if previous.exists && previous.comment != counter.Rule {
			return rollback(fmt.Errorf("rule id %q changed comment from %q to %q", counter.ID, previous.comment, counter.Rule))
		}
		packetDelta, byteDelta := uint64(0), uint64(0)
		reset := 0
		epoch := int64(0)
		if previous.exists {
			epoch = previous.epoch
			if !previous.active {
				packetDelta, byteDelta = 0, 0
				reset = 1
				epoch++
				if _, err := tx.Exec(`INSERT INTO epochs (rule_id, epoch, started_at, reason, previous_packets, previous_bytes) VALUES (?, ?, ?, 'rule_reappeared', ?, ?)`, counter.ID, epoch, now, decimal(previous.packets), decimal(previous.bytes)); err != nil {
					return rollback(fmt.Errorf("record reappeared rule epoch for %q: %w", counter.ID, err))
				}
			} else if counter.Packets < previous.packets || counter.Bytes < previous.bytes {
				packetDelta, byteDelta = 0, 0
				reset = 1
				epoch++
				if _, err := tx.Exec(`INSERT INTO epochs (rule_id, epoch, started_at, reason, previous_packets, previous_bytes) VALUES (?, ?, ?, 'counter_reset', ?, ?)`, counter.ID, epoch, now, decimal(previous.packets), decimal(previous.bytes)); err != nil {
					return rollback(fmt.Errorf("record counter epoch for %q: %w", counter.ID, err))
				}
			} else {
				packetDelta = counter.Packets - previous.packets
				byteDelta = counter.Bytes - previous.bytes
			}
		}
		if err := s.upsertRuleTx(tx, counter, now, packetDelta, byteDelta, reset, epoch, previous.exists); err != nil {
			return rollback(err)
		}
		if _, err := tx.Exec(`INSERT INTO samples (rule_id, sampled_at, packets, bytes, packet_delta, byte_delta, epoch, reset) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, counter.ID, now, decimal(counter.Packets), decimal(counter.Bytes), decimal(packetDelta), decimal(byteDelta), epoch, reset); err != nil {
			return rollback(fmt.Errorf("record counter sample for %q: %w", counter.ID, err))
		}
	}
	if err := s.retireMissingRulesTx(tx, seen); err != nil {
		return rollback(err)
	}
	for key, value := range map[string]string{
		"status":           "healthy",
		"last_attempt_at":  strconv.FormatInt(now, 10),
		"last_success_at":  strconv.FormatInt(now, 10),
		"last_error":       "",
		"last_fingerprint": snapshot.Fingerprint,
	} {
		if err := s.setHealthTx(tx, key, value); err != nil {
			return rollback(err)
		}
	}
	if err := s.pruneTx(tx, at); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry sample: %w", err)
	}
	return nil
}

func (s *Store) retireMissingRulesTx(tx *sql.Tx, seen map[string]struct{}) error {
	rows, err := tx.Query(`SELECT id FROM rules WHERE active = 1`)
	if err != nil {
		return fmt.Errorf("list active telemetry rules: %w", err)
	}
	missing := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan active telemetry rule: %w", err)
		}
		if _, exists := seen[id]; !exists {
			missing = append(missing, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("read active telemetry rules: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close active telemetry rules: %w", err)
	}
	for _, id := range missing {
		if _, err := tx.Exec(`UPDATE rules SET active = 0 WHERE id = ?`, id); err != nil {
			return fmt.Errorf("retire telemetry rule %q: %w", id, err)
		}
	}
	return nil
}

func (s *Store) RecordHealthError(at time.Time, collectorErr error) error {
	at = at.UTC()
	if collectorErr == nil {
		return errors.New("collector error is required")
	}
	message := strings.Join(strings.Fields(collectorErr.Error()), " ")
	if len(message) > 512 {
		message = message[:512]
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin telemetry health transaction: %w", err)
	}
	for key, value := range map[string]string{
		"status":          "degraded",
		"last_attempt_at": strconv.FormatInt(at.UnixNano(), 10),
		"last_error":      message,
	} {
		if err := s.setHealthTx(tx, key, value); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry health: %w", err)
	}
	return nil
}

type previousRule struct {
	exists  bool
	active  bool
	comment string
	packets uint64
	bytes   uint64
	epoch   int64
}

func (s *Store) previousRuleTx(tx *sql.Tx, id string) (previousRule, error) {
	var previous previousRule
	var packets, bytes string
	var active int
	err := tx.QueryRow(`SELECT comment, last_packets, last_bytes, epoch, active FROM rules WHERE id = ?`, id).Scan(&previous.comment, &packets, &bytes, &previous.epoch, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return previousRule{}, nil
	}
	if err != nil {
		return previousRule{}, fmt.Errorf("read previous telemetry sample for %q: %w", id, err)
	}
	previous.exists = true
	previous.active = active != 0
	var parseErr error
	previous.packets, parseErr = parseDecimal(packets)
	if parseErr != nil {
		return previousRule{}, fmt.Errorf("read previous packet counter for %q: %w", id, parseErr)
	}
	previous.bytes, parseErr = parseDecimal(bytes)
	if parseErr != nil {
		return previousRule{}, fmt.Errorf("read previous byte counter for %q: %w", id, parseErr)
	}
	return previous, nil
}

func (s *Store) upsertRuleTx(tx *sql.Tx, counter firewall.Counter, at int64, packetDelta, byteDelta uint64, reset int, epoch int64, exists bool) error {
	if exists {
		_, err := tx.Exec(`UPDATE rules SET kind = ?, comment = ?, family = ?, table_name = ?, chain_name = ?, last_seen_at = ?, last_packets = ?, last_bytes = ?, last_packet_delta = ?, last_byte_delta = ?, last_reset = ?, epoch = ?, last_sample_at = ?, active = 1 WHERE id = ?`, counter.Kind, counter.Rule, counter.Family, counter.Table, counter.Chain, at, decimal(counter.Packets), decimal(counter.Bytes), decimal(packetDelta), decimal(byteDelta), reset, epoch, at, counter.ID)
		if err != nil {
			return fmt.Errorf("update telemetry rule %q: %w", counter.ID, err)
		}
		return nil
	}
	_, err := tx.Exec(`INSERT INTO rules (id, kind, comment, family, table_name, chain_name, first_seen_at, last_seen_at, last_packets, last_bytes, last_packet_delta, last_byte_delta, last_reset, epoch, last_sample_at, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`, counter.ID, counter.Kind, counter.Rule, counter.Family, counter.Table, counter.Chain, at, at, decimal(counter.Packets), decimal(counter.Bytes), decimal(packetDelta), decimal(byteDelta), reset, epoch, at)
	if err != nil {
		return fmt.Errorf("insert telemetry rule %q: %w", counter.ID, err)
	}
	return nil
}

func (s *Store) pruneTx(tx *sql.Tx, at time.Time) error {
	sampleCutoff := at.Add(-s.retention).UnixNano()
	eventCutoff := at.Add(-EventRetention).UnixNano()
	for statement, cutoff := range map[string]int64{
		"DELETE FROM samples WHERE sampled_at < ?": sampleCutoff,
		"DELETE FROM epochs WHERE started_at < ?":  sampleCutoff,
		"DELETE FROM events WHERE observed_at < ?": eventCutoff,
	} {
		if _, err := tx.Exec(statement, cutoff); err != nil {
			return fmt.Errorf("prune telemetry retention: %w", err)
		}
	}
	return nil
}

func (s *Store) healthTx(tx *sql.Tx, key string) (string, bool) {
	var value string
	if err := tx.QueryRow(`SELECT value FROM health WHERE key = ?`, key).Scan(&value); err != nil {
		return "", false
	}
	return value, true
}

func (s *Store) setHealthTx(tx *sql.Tx, key, value string) error {
	if _, err := tx.Exec(`INSERT INTO health (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return fmt.Errorf("update telemetry health %q: %w", key, err)
	}
	return nil
}

type CollectorHealth struct {
	Status                 string     `json:"status"`
	LastAttemptAt          *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt          *time.Time `json:"last_success_at,omitempty"`
	SampleAgeSeconds       *int64     `json:"sample_age_seconds,omitempty"`
	LastStructuralChangeAt *time.Time `json:"last_structural_change_at,omitempty"`
	LastFingerprint        string     `json:"last_fingerprint,omitempty"`
	LastError              string     `json:"last_error,omitempty"`
}

func (s *Store) Health(at time.Time) (CollectorHealth, error) {
	values, err := s.healthValues()
	if err != nil {
		return CollectorHealth{}, err
	}
	health := CollectorHealth{Status: values["status"], LastFingerprint: values["last_fingerprint"], LastError: values["last_error"]}
	if health.Status == "" {
		health.Status = "starting"
	}
	for key, target := range map[string]**time.Time{"last_attempt_at": &health.LastAttemptAt, "last_success_at": &health.LastSuccessAt, "last_structural_change_at": &health.LastStructuralChangeAt} {
		if timestamp, ok := parseTimestamp(values[key]); ok {
			*target = &timestamp
		}
	}
	if health.LastSuccessAt != nil {
		age := at.UTC().Sub(*health.LastSuccessAt).Seconds()
		if age < 0 {
			age = 0
		}
		value := int64(age)
		health.SampleAgeSeconds = &value
		if age > SampleStaleAfter.Seconds() {
			health.Status = "degraded"
			if health.LastError == "" {
				health.LastError = "last telemetry sample is stale"
			}
		}
	}
	return health, nil
}

func (s *Store) healthValues() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM health`)
	if err != nil {
		return nil, fmt.Errorf("read telemetry health: %w", err)
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan telemetry health: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read telemetry health rows: %w", err)
	}
	return values, nil
}

func parseTimestamp(value string) (time.Time, bool) {
	nanos, err := strconv.ParseInt(value, 10, 64)
	if err != nil || nanos == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, nanos).UTC(), true
}

func decimal(value uint64) string { return strconv.FormatUint(value, 10) }

func parseDecimal(value string) (uint64, error) { return strconv.ParseUint(value, 10, 64) }

type RuleView struct {
	ID              string    `json:"id"`
	Kind            string    `json:"kind"`
	Comment         string    `json:"comment"`
	Family          string    `json:"family"`
	Table           string    `json:"table"`
	Chain           string    `json:"chain"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	LastPackets     uint64    `json:"last_packets"`
	LastBytes       uint64    `json:"last_bytes"`
	LastPacketDelta uint64    `json:"last_packet_delta"`
	LastByteDelta   uint64    `json:"last_byte_delta"`
	LastReset       bool      `json:"last_reset"`
	Epoch           int64     `json:"epoch"`
	Active          bool      `json:"active"`
}

func (s *Store) Rules(limit int) ([]RuleView, error) {
	limit = boundLimit(limit, MaxRuleResults)
	rows, err := s.db.Query(`SELECT id, kind, comment, family, table_name, chain_name, first_seen_at, last_seen_at, last_packets, last_bytes, last_packet_delta, last_byte_delta, last_reset, epoch, active FROM rules ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("read telemetry rules: %w", err)
	}
	defer rows.Close()
	result := make([]RuleView, 0)
	for rows.Next() {
		view, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, view)
	}
	return result, rows.Err()
}

func (s *Store) Rule(id string) (RuleView, error) {
	row := s.db.QueryRow(`SELECT id, kind, comment, family, table_name, chain_name, first_seen_at, last_seen_at, last_packets, last_bytes, last_packet_delta, last_byte_delta, last_reset, epoch, active FROM rules WHERE id = ?`, id)
	view, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RuleView{}, os.ErrNotExist
	}
	return view, err
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRule(row rowScanner) (RuleView, error) {
	var view RuleView
	var first, last int64
	var packets, bytes, packetDelta, byteDelta string
	var reset, active int
	if err := row.Scan(&view.ID, &view.Kind, &view.Comment, &view.Family, &view.Table, &view.Chain, &first, &last, &packets, &bytes, &packetDelta, &byteDelta, &reset, &view.Epoch, &active); err != nil {
		return RuleView{}, err
	}
	view.FirstSeenAt = time.Unix(0, first).UTC()
	view.LastSeenAt = time.Unix(0, last).UTC()
	var err error
	if view.LastPackets, err = parseDecimal(packets); err != nil {
		return RuleView{}, fmt.Errorf("decode rule packet counter: %w", err)
	}
	if view.LastBytes, err = parseDecimal(bytes); err != nil {
		return RuleView{}, fmt.Errorf("decode rule byte counter: %w", err)
	}
	if view.LastPacketDelta, err = parseDecimal(packetDelta); err != nil {
		return RuleView{}, fmt.Errorf("decode rule packet delta: %w", err)
	}
	if view.LastByteDelta, err = parseDecimal(byteDelta); err != nil {
		return RuleView{}, fmt.Errorf("decode rule byte delta: %w", err)
	}
	view.LastReset = reset != 0
	view.Active = active != 0
	return view, nil
}

type ActivitySample struct {
	At           time.Time `json:"at"`
	Packets      uint64    `json:"packets"`
	Bytes        uint64    `json:"bytes"`
	PacketDelta  uint64    `json:"packet_delta"`
	ByteDelta    uint64    `json:"byte_delta"`
	Epoch        int64     `json:"epoch"`
	CounterReset bool      `json:"counter_reset"`
}

func (s *Store) Activity(id string, since time.Time, limit int) ([]ActivitySample, error) {
	limit = boundLimit(limit, MaxActivityResults)
	rows, err := s.db.Query(`SELECT sampled_at, packets, bytes, packet_delta, byte_delta, epoch, reset FROM samples WHERE rule_id = ? AND sampled_at >= ? ORDER BY sampled_at DESC LIMIT ?`, id, since.UTC().UnixNano(), limit)
	if err != nil {
		return nil, fmt.Errorf("read telemetry activity: %w", err)
	}
	defer rows.Close()
	result := make([]ActivitySample, 0)
	for rows.Next() {
		var at int64
		var packets, bytes, packetDelta, byteDelta string
		var sample ActivitySample
		var reset int
		if err := rows.Scan(&at, &packets, &bytes, &packetDelta, &byteDelta, &sample.Epoch, &reset); err != nil {
			return nil, fmt.Errorf("scan telemetry activity: %w", err)
		}
		sample.At = time.Unix(0, at).UTC()
		var parseErr error
		if sample.Packets, parseErr = parseDecimal(packets); parseErr != nil {
			return nil, parseErr
		}
		if sample.Bytes, parseErr = parseDecimal(bytes); parseErr != nil {
			return nil, parseErr
		}
		if sample.PacketDelta, parseErr = parseDecimal(packetDelta); parseErr != nil {
			return nil, parseErr
		}
		if sample.ByteDelta, parseErr = parseDecimal(byteDelta); parseErr != nil {
			return nil, parseErr
		}
		sample.CounterReset = reset != 0
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}

type WindowSummary struct {
	Window          string `json:"window"`
	AcceptedPackets uint64 `json:"accepted_packets"`
	AcceptedBytes   uint64 `json:"accepted_bytes"`
	DroppedPackets  uint64 `json:"dropped_packets"`
	DroppedBytes    uint64 `json:"dropped_bytes"`
}

func (s *Store) WindowSummary(window string, since time.Time) (WindowSummary, error) {
	rows, err := s.db.Query(`SELECT kind, COALESCE(SUM(CAST(packet_delta AS INTEGER)), 0), COALESCE(SUM(CAST(byte_delta AS INTEGER)), 0) FROM samples JOIN rules ON rules.id = samples.rule_id WHERE sampled_at >= ? GROUP BY kind`, since.UTC().UnixNano())
	if err != nil {
		return WindowSummary{}, fmt.Errorf("read telemetry window: %w", err)
	}
	defer rows.Close()
	result := WindowSummary{Window: window}
	for rows.Next() {
		var kind string
		var packets, bytes int64
		if err := rows.Scan(&kind, &packets, &bytes); err != nil {
			return WindowSummary{}, err
		}
		if packets < 0 || bytes < 0 {
			return WindowSummary{}, errors.New("telemetry window contains a negative delta")
		}
		if kind == "allow" {
			result.AcceptedPackets += uint64(packets)
			result.AcceptedBytes += uint64(bytes)
		} else if kind == "deny" || kind == "drop" {
			result.DroppedPackets += uint64(packets)
			result.DroppedBytes += uint64(bytes)
		}
	}
	return result, rows.Err()
}

type SecurityActivity struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Comment     string `json:"comment"`
	PacketDelta uint64 `json:"packet_delta"`
	ByteDelta   uint64 `json:"byte_delta"`
}

func (s *Store) SecurityActivity(since time.Time) ([]SecurityActivity, error) {
	rows, err := s.db.Query(`SELECT rules.id, rules.kind, rules.comment, COALESCE(SUM(CAST(samples.packet_delta AS INTEGER)), 0), COALESCE(SUM(CAST(samples.byte_delta AS INTEGER)), 0) FROM samples JOIN rules ON rules.id = samples.rule_id WHERE samples.sampled_at >= ? AND rules.kind IN ('deny', 'drop') GROUP BY rules.id, rules.kind, rules.comment HAVING SUM(CAST(samples.packet_delta AS INTEGER)) > 0 OR SUM(CAST(samples.byte_delta AS INTEGER)) > 0 ORDER BY SUM(CAST(samples.packet_delta AS INTEGER)) DESC, rules.id LIMIT ?`, since.UTC().UnixNano(), MaxSecurityResults)
	if err != nil {
		return nil, fmt.Errorf("read security telemetry activity: %w", err)
	}
	defer rows.Close()
	result := make([]SecurityActivity, 0)
	for rows.Next() {
		var activity SecurityActivity
		var packets, bytes int64
		if err := rows.Scan(&activity.ID, &activity.Kind, &activity.Comment, &packets, &bytes); err != nil {
			return nil, err
		}
		if packets < 0 || bytes < 0 {
			return nil, errors.New("security telemetry contains a negative delta")
		}
		activity.PacketDelta, activity.ByteDelta = uint64(packets), uint64(bytes)
		result = append(result, activity)
	}
	return result, rows.Err()
}

type EventView struct {
	ID                  int64     `json:"id"`
	At                  time.Time `json:"at"`
	Kind                string    `json:"kind"`
	RuleID              string    `json:"rule_id,omitempty"`
	Fingerprint         string    `json:"fingerprint,omitempty"`
	PreviousFingerprint string    `json:"previous_fingerprint,omitempty"`
	Detail              string    `json:"detail,omitempty"`
}

func (s *Store) Events(since time.Time, limit int) ([]EventView, error) {
	limit = boundLimit(limit, MaxEventResults)
	rows, err := s.db.Query(`SELECT id, observed_at, kind, rule_id, fingerprint, previous_fingerprint, detail FROM events WHERE observed_at >= ? ORDER BY observed_at ASC, id ASC LIMIT ?`, since.UTC().UnixNano(), limit)
	if err != nil {
		return nil, fmt.Errorf("read telemetry events: %w", err)
	}
	defer rows.Close()
	result := make([]EventView, 0)
	for rows.Next() {
		var event EventView
		var at int64
		if err := rows.Scan(&event.ID, &at, &event.Kind, &event.RuleID, &event.Fingerprint, &event.PreviousFingerprint, &event.Detail); err != nil {
			return nil, err
		}
		event.At = time.Unix(0, at).UTC()
		result = append(result, event)
	}
	return result, rows.Err()
}

func boundLimit(value, maximum int) int {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}
