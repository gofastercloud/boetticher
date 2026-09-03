// Package application contains the small typed boundary shared by the
// operator interfaces. It describes user intent; infrastructure-specific
// execution remains in the CLI application adapter and its existing domain
// packages.
package application

import (
	"context"

	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

type Operation string

const (
	OperationStatus        Operation = "status"
	OperationPlan          Operation = "plan"
	OperationModuleList    Operation = "module-list"
	OperationDiagnose      Operation = "diagnose"
	OperationConfigure     Operation = "configure-module"
	OperationDeploy        Operation = "deploy"
	OperationInit          Operation = "init"
	OperationEnroll        Operation = "enroll"
	OperationRecover       Operation = "recover"
	OperationNetworkStatus Operation = "network-status"
)

// Request is the stable, typed input to one application use case. The
// initial shared UI surface intentionally exposes only read-only status,
// planning, module inspection, and diagnosis; mutating operations can be
// added here with an explicit form rather than a shell command string.
type Request struct {
	Operation Operation
	SiteDir   string
	Live      bool
	DryRun    bool
	Confirm   bool
	Module    string
	Enabled   *bool
}

type Event struct {
	Kind    string
	Message string
}

type Result struct {
	Operation Operation
	Output    string
	Report    statusmodel.Report
	Metrics   *Metrics
}

type Metrics struct {
	Health       string
	ActiveAlerts int
	Nodes        int
	VMs          int
	Containers   int
	Resources    int
	LastUpdate   string
}

// Executor is the one UI-to-application seam. It is deliberately narrow and
// concrete: operations are a closed set, requests are typed, and progress is
// an explicit event stream rather than parsed terminal output.
type Executor interface {
	Execute(context.Context, Request, func(Event)) (Result, error)
}

type Command struct {
	Name        string
	Description string
	Request     Request
}
