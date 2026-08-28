package firewalltelemetry

import (
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewall"
)

func TestStorePersistsIncrementsResetsEpochsAndStructuralEvents(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	counter := func(packets, bytes uint64) firewall.Counter {
		return firewall.Counter{Rule: "boetticher:allow:forward-test", ID: "forward-test", Kind: "allow", Family: "inet", Table: firewall.FilterTable, Chain: "forward", Packets: packets, Bytes: bytes}
	}
	if err := store.RecordSnapshot(base, firewall.NFTSnapshot{Fingerprint: "fingerprint-a", Counters: []firewall.Counter{counter(10, 100)}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSnapshot(base.Add(15*time.Second), firewall.NFTSnapshot{Fingerprint: "fingerprint-a", Counters: []firewall.Counter{counter(16, 160)}}); err != nil {
		t.Fatal(err)
	}
	view, err := store.Rule("forward-test")
	if err != nil {
		t.Fatal(err)
	}
	if view.LastPacketDelta != 6 || view.LastByteDelta != 60 || view.Epoch != 0 || view.LastReset {
		t.Fatalf("incremental rule view = %#v", view)
	}
	if err := store.RecordSnapshot(base.Add(30*time.Second), firewall.NFTSnapshot{Fingerprint: "fingerprint-a", Counters: []firewall.Counter{counter(2, 20)}}); err != nil {
		t.Fatal(err)
	}
	view, err = store.Rule("forward-test")
	if err != nil {
		t.Fatal(err)
	}
	if view.LastPacketDelta != 0 || view.LastByteDelta != 0 || view.Epoch != 1 || !view.LastReset {
		t.Fatalf("reset rule view = %#v", view)
	}
	activity, err := store.Activity("forward-test", base.Add(-time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(activity) != 3 || activity[1].PacketDelta != 6 || !activity[2].CounterReset {
		t.Fatalf("activity = %#v", activity)
	}
	if err := store.RecordSnapshot(base.Add(45*time.Second), firewall.NFTSnapshot{Fingerprint: "fingerprint-b", Counters: []firewall.Counter{counter(4, 40)}}); err != nil {
		t.Fatal(err)
	}
	events, err := store.Events(base.Add(-time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "ruleset_change" || events[0].PreviousFingerprint != "fingerprint-a" || events[0].Fingerprint != "fingerprint-b" {
		t.Fatalf("structural events = %#v", events)
	}
	health, err := store.Health(base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if health.Status != "healthy" || health.LastFingerprint != "fingerprint-b" || health.LastStructuralChangeAt == nil {
		t.Fatalf("health = %#v", health)
	}
}

func TestStoreRetentionRemovesOldRawSamplesButKeepsCurrentRuleMetadata(t *testing.T) {
	store := openTestStore(t)
	store.retention = time.Hour
	base := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	counter := firewall.Counter{Rule: "boetticher:drop:forward-test", ID: "forward-test", Kind: "drop", Family: "inet", Table: firewall.FilterTable, Chain: "forward", Packets: 1, Bytes: 2}
	if err := store.RecordSnapshot(base, firewall.NFTSnapshot{Fingerprint: "fingerprint", Counters: []firewall.Counter{counter}}); err != nil {
		t.Fatal(err)
	}
	counter.Packets = 3
	counter.Bytes = 4
	if err := store.RecordSnapshot(base.Add(2*time.Hour), firewall.NFTSnapshot{Fingerprint: "fingerprint", Counters: []firewall.Counter{counter}}); err != nil {
		t.Fatal(err)
	}
	var samples int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&samples); err != nil {
		t.Fatal(err)
	}
	if samples != 1 {
		t.Fatalf("raw samples after retention = %d, want 1", samples)
	}
	if _, err := store.Rule("forward-test"); err != nil {
		t.Fatalf("current rule metadata was pruned: %v", err)
	}
}

func TestStoreHealthErrorIsBoundedAndDoesNotEraseLastSuccess(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	counter := firewall.Counter{Rule: "boetticher:allow:test", ID: "test", Kind: "allow", Family: "inet", Table: firewall.FilterTable, Chain: "forward"}
	if err := store.RecordSnapshot(base, firewall.NFTSnapshot{Fingerprint: "fingerprint", Counters: []firewall.Counter{counter}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordHealthError(base.Add(time.Minute), &testError{message: " noisy error " + repeated("x", 1000)}); err != nil {
		t.Fatal(err)
	}
	health, err := store.Health(base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if health.Status != "degraded" || health.LastSuccessAt == nil || len(health.LastError) > 512 {
		t.Fatalf("bounded health error = %#v", health)
	}
}

func TestStoreHealthMarksStoppedCollectorStale(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	if err := store.RecordSnapshot(base, firewall.NFTSnapshot{Fingerprint: "fingerprint"}); err != nil {
		t.Fatal(err)
	}
	health, err := store.Health(base.Add(SampleStaleAfter + time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if health.Status != "degraded" || health.SampleAgeSeconds == nil || health.LastError != "last telemetry sample is stale" {
		t.Fatalf("stale collector health = %#v", health)
	}
}

type testError struct{ message string }

func (e *testError) Error() string { return e.message }

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := OpenStore(t.TempDir() + "/telemetry.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func repeated(value string, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = value[0]
	}
	return string(result)
}
