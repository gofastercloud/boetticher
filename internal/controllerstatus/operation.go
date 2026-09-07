package controllerstatus

import (
	"errors"
	"fmt"
	"strings"
)

// Operation is the small CLI-facing display lifecycle. Notifications remain
// best-effort: the display is never part of the operation's success criteria.
type Operation struct {
	name  string
	mode  DisplayMode
	total int
	tests []TestResult
}

func StartApply(name string, steps int) *Operation {
	if steps <= 0 {
		steps = PixelCount
	}
	op := &Operation{name: name, mode: Applying, total: steps}
	op.notify(OperationEvent{Event: "operation-start", Name: name, Mode: Applying, TotalSteps: steps})
	return op
}

// StartStandard preserves operation details for other lifecycle commands
// without taking the Blinkt away from its stacked status display.
func StartStandard(name string, steps int) *Operation {
	if steps <= 0 {
		steps = PixelCount
	}
	op := &Operation{name: name, mode: Standard, total: steps}
	op.notify(OperationEvent{Event: "operation-start", Name: name, Mode: Standard, TotalSteps: steps})
	return op
}

func StartTest(name string, testNames []string) (*Operation, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("test display operation name is required")
	}
	if len(testNames) == 0 || len(testNames) > PixelCount {
		return nil, fmt.Errorf("test display operation requires one to %d named tests", PixelCount)
	}
	tests := make([]TestResult, len(testNames))
	seen := make(map[string]struct{}, len(testNames))
	for index, testName := range testNames {
		testName = strings.TrimSpace(testName)
		if testName == "" {
			return nil, errors.New("test display operation test names must not be empty")
		}
		if _, ok := seen[testName]; ok {
			return nil, fmt.Errorf("test display operation test %q is duplicated", testName)
		}
		seen[testName] = struct{}{}
		tests[index] = TestResult{Name: testName, State: Checking}
	}
	op := &Operation{name: name, mode: Testing, total: len(tests), tests: tests}
	op.notify(OperationEvent{Event: "operation-start", Name: name, Mode: Testing, TotalSteps: len(tests), Tests: op.copyTests()})
	return op, nil
}

func (o *Operation) Progress(step int, detail string) {
	if o == nil {
		return
	}
	o.notify(OperationEvent{Event: "operation-progress", Name: o.name, Mode: o.mode, CurrentStep: step, TotalSteps: o.total, Detail: detail, Tests: o.copyTests()})
}

func (o *Operation) TestResult(name string, passed bool) error {
	if o == nil || o.mode != Testing {
		return errors.New("test result requires a Testing display operation")
	}
	for index := range o.tests {
		if o.tests[index].Name == name {
			if o.tests[index].State != Checking {
				return fmt.Errorf("test %q already has a result", name)
			}
			if passed {
				o.tests[index].State = Healthy
			} else {
				o.tests[index].State = Failed
			}
			o.Progress(index+1, "")
			return nil
		}
	}
	return fmt.Errorf("unknown test %q", name)
}

func (o *Operation) End(err error) {
	if o == nil {
		return
	}
	event := "operation-success"
	if err != nil {
		event = "operation-failure"
	}
	o.notify(OperationEvent{Event: event, Name: o.name, Mode: o.mode, CurrentStep: o.total, TotalSteps: o.total, Detail: operationDetail(err), Tests: o.copyTests()})
}

func (o *Operation) notify(event OperationEvent) { NotifyBestEffort(event) }

func (o *Operation) copyTests() []TestResult {
	return append([]TestResult(nil), o.tests...)
}

func operationDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
