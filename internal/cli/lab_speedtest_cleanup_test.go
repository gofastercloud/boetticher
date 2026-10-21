package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/labspeedtest"
)

type fakeHostRunner struct {
	command string
	stdout  string
	err     error
}

func (f *fakeHostRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	f.command = command
	return controllerhost.Result{Stdout: []byte(f.stdout)}, f.err
}

func TestCleanupLabSpeedtestUsesTheNativeHelperAndReportsOutcome(t *testing.T) {
	cases := map[string]struct {
		runner    fakeHostRunner
		recovered bool
		absent    bool
		wantErr   string
	}{
		"nothing to remove": {runner: fakeHostRunner{stdout: `{"phase":"cleanup"}` + "\n"}},
		"leftover removed":  {runner: fakeHostRunner{stdout: `{"phase":"cleanup","recovered_leftovers":true}` + "\n"}, recovered: true},
		"stale helper":      {runner: fakeHostRunner{stdout: `{"phase":"cleanup","helper_absent":true}` + "\n"}, absent: true},
		"ambiguous":         {runner: fakeHostRunner{stdout: `{"phase":"error","error":"lab speedtest cleanup failed: ownership is ambiguous"}` + "\n", err: errors.New("exit status 1")}, wantErr: "ambiguous"},
		"lock held":         {runner: fakeHostRunner{stdout: `{"phase":"error","error":"a firewall test or lab speedtest is already running on the Host"}` + "\n", err: errors.New("exit status 1")}, wantErr: "already running"},
		"transport failure": {runner: fakeHostRunner{err: errors.New("ssh: connect refused")}, wantErr: "connect refused"},
		"garbage":           {runner: fakeHostRunner{stdout: "hello\n"}, wantErr: "decode"},
		"wrong phase":       {runner: fakeHostRunner{stdout: `{"phase":"setup"}` + "\n"}, wantErr: "unexpected"},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			runner := item.runner
			event, err := cleanupLabSpeedtest(context.Background(), &runner)
			if runner.command != labspeedtest.CleanupCommand {
				t.Fatalf("command = %q", runner.command)
			}
			if item.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), item.wantErr) {
					t.Fatalf("err = %v, want %q", err, item.wantErr)
				}
				return
			}
			if err != nil || event.Recovered != item.recovered || event.HelperAbsent != item.absent {
				t.Fatalf("event=%#v err=%v", event, err)
			}
		})
	}
}
