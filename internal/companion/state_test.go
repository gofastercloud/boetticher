package companion

import (
	"testing"
	"time"
)

func TestNavigationAndWake(t *testing.T) {
	s := NewState(Config{Display: true})
	if err := s.Action("select", "dns"); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().View != "dns" {
		t.Fatal("selection did not reach HDMI state")
	}
	if err := s.Action("shell", "reboot"); err == nil {
		t.Fatal("arbitrary action accepted")
	}
	_ = s.Action("dim", "")
	_ = s.Action("dim", "")
	if s.Snapshot().Brightness != "blank" {
		t.Fatal("did not blank")
	}
	_ = s.Action("select", "pi")
	if got := s.Snapshot(); got.Brightness != "normal" || got.View != "dns" {
		t.Fatal("wake press was not consumed")
	}
	_ = s.Action("home", "")
	if s.Snapshot().View != "overview" {
		t.Fatal("home did not restore overview")
	}
}

func TestStaleDataCannotRemainHealthy(t *testing.T) {
	s := NewState(Config{})
	now := time.Now()
	s.Update(Item{ID: "pulse", Status: Healthy, ObservedAt: now.Add(-2 * time.Minute)})
	if s.Snapshot().Items[5].Status == Healthy {
		t.Fatal("stale data reported healthy")
	}
	s.Update(Item{ID: "pulse", Status: Healthy, ObservedAt: now})
	if s.Snapshot().Items[5].Status != Healthy {
		t.Fatal("fresh healthy sample rejected")
	}
}
