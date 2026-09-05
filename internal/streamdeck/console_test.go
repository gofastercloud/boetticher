package streamdeck

import (
	"github.com/gofastercloud/boetticher/internal/companion"
	"testing"
)

func TestConsoleNavigationRemainsInBottomRow(t *testing.T) {
	s := companion.NewState(companion.Config{})
	home := ConsoleTiles(s.Snapshot())
	_ = s.Action("select", "resources")
	resources := ConsoleTiles(s.Snapshot())
	for i, action := range []string{"home", "back", "previous", "next", "dim"} {
		if home[10+i].Action != action || resources[10+i] != home[10+i] {
			t.Fatal("navigation moved")
		}
	}
	if home[3].Target != "dns" || home[9].Action != "refresh" {
		t.Fatal("wrong local actions")
	}
}
