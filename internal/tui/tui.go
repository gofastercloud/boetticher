// Package tui contains the experimental interactive operator interface.
// Domain mutations remain owned by internal/cli; this package only owns
// navigation, presentation, and bounded command orchestration.
package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/google/shlex"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

// Runner executes an existing Boetticher command. It is injected by the CLI
// package to avoid a package cycle and to keep one command implementation.
type Runner func(args []string, input io.Reader, out, errOut io.Writer) error

// Observability is the small, presentation-ready projection of the 0.4.1
// monitoring contract. Credentials and transport details stay in the CLI.
type Observability struct {
	Health       string
	ActiveAlerts int
	Nodes        int
	VMs          int
	Containers   int
	Resources    int
	LastUpdate   string
}

// ObservabilityReader reads live metrics without changing site state.
type ObservabilityReader func(context.Context) (Observability, error)

type Options struct {
	SiteDir       string
	Offline       bool
	Runner        Runner
	Commands      []string
	Observability ObservabilityReader
}

type mode uint8

const (
	dashboardMode mode = iota
	commandsMode
	argumentMode
	outputMode
)

type commandItem struct{ usage string }

func (i commandItem) FilterValue() string { return i.usage }
func (i commandItem) Title() string       { return commandPath(i.usage) }
func (i commandItem) Description() string {
	if commandPath(i.usage) == "network test" {
		return "Live path diagnostic; creates temporary probes and cleans them up"
	}
	return ""
}

type snapshot struct {
	site       model.Site
	report     statusmodel.Report
	loadedAt   time.Time
	loadError  error
	liveOutput string
	metrics    *Observability
}

type modelState struct {
	options       Options
	snapshot      snapshot
	commands      list.Model
	input         textinput.Model
	viewport      viewport.Model
	mode          mode
	width         int
	height        int
	output        string
	message       string
	running       bool
	command       string
	progress      <-chan string
	progressLines []string
}

type refreshResult struct {
	report  statusmodel.Report
	output  string
	metrics *Observability
	err     error
}

type commandResult struct {
	command string
	output  string
	err     error
}

type commandProgress struct {
	channel <-chan string
	line    string
	done    bool
}

// Run starts the alternate-screen TUI.
func Run(options Options) error {
	if options.SiteDir == "" {
		options.SiteDir = "."
	}
	if options.Runner == nil {
		return errors.New("TUI command runner is not configured")
	}
	initial := loadSnapshot(options.SiteDir)
	items := make([]list.Item, 0, len(options.Commands))
	for _, usage := range options.Commands {
		items = append(items, commandItem{usage: usage})
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	commands := list.New(items, delegate, 34, 16)
	commands.Title = "Commands"
	commands.SetShowStatusBar(false)
	commands.SetShowPagination(false)
	commands.SetShowHelp(true)
	input := textinput.New()
	input.Prompt = "> "
	input.Placeholder = "command arguments"
	input.CharLimit = 4096
	viewportModel := viewport.New()
	state := modelState{options: options, snapshot: initial, commands: commands, input: input, viewport: viewportModel, mode: dashboardMode}
	program := tea.NewProgram(&state)
	_, err := program.Run()
	return err
}

func (m *modelState) Init() tea.Cmd {
	if m.options.Offline {
		return nil
	}
	return m.refresh()
}

func (m *modelState) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
	case refreshResult:
		m.running = false
		m.snapshot.liveOutput = msg.output
		if msg.report.StatusModelVersion != "" {
			m.snapshot.report = msg.report
			m.snapshot.loadedAt = time.Now().UTC()
		}
		m.snapshot.metrics = msg.metrics
		if msg.err != nil {
			m.message = "Live refresh failed: " + safeError(msg.err)
		} else {
			m.message = "Live refresh complete"
		}
	case commandResult:
		m.running = false
		m.progress = nil
		m.mode = outputMode
		m.command = msg.command
		m.output = strings.TrimSpace(msg.output)
		if msg.err != nil {
			if m.output != "" {
				m.output += "\n\n"
			}
			m.output += "FAIL\n" + safeError(msg.err)
			m.message = "Command failed"
		} else {
			m.message = "Command complete"
		}
		m.viewport.SetContent(m.output)
		m.viewport.GotoTop()
	case commandProgress:
		if !msg.done && m.running {
			m.progressLines = append(m.progressLines, msg.line)
			if len(m.progressLines) > 12 {
				m.progressLines = m.progressLines[len(m.progressLines)-12:]
			}
			return m, waitForCommandProgress(msg.channel)
		}
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	}
	if m.mode == commandsMode {
		var cmd tea.Cmd
		m.commands, cmd = m.commands.Update(msg)
		return m, cmd
	}
	if m.mode == argumentMode {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	if m.mode == outputMode {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *modelState) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.running {
		return m, nil
	}
	key := msg.String()
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "d":
		m.mode = dashboardMode
	case "c":
		m.mode = commandsMode
		m.commands.FilterInput.Focus()
	case "r":
		if !m.options.Offline {
			m.message = "Refreshing live status..."
			m.running = true
			return m, m.refresh()
		}
		m.message = "Offline mode: live refresh disabled"
	case "esc":
		m.mode = dashboardMode
	case "enter":
		if m.mode == commandsMode {
			if selected, ok := m.commands.SelectedItem().(commandItem); ok {
				m.command = commandPath(selected.usage)
				m.input.SetValue(m.command)
				m.input.Focus()
				m.mode = argumentMode
			}
		} else if m.mode == argumentMode {
			return m, m.execute(m.input.Value())
		}
	}
	return m, nil
}

func (m *modelState) execute(line string) tea.Cmd {
	args, err := shlex.Split(strings.TrimSpace(line))
	if err != nil {
		m.message = "Invalid command line: " + err.Error()
		return nil
	}
	if len(args) == 0 {
		m.message = "Enter a command first"
		return nil
	}
	if args[0] == "boetticher" {
		args = args[1:]
	}
	args = addSelectedSite(args, m.options.SiteDir)
	command := strings.Join(args, " ")
	m.running = true
	m.message = "Running " + command
	m.progressLines = nil
	progress := make(chan string, 128)
	m.progress = progress
	commandRun := func() tea.Msg {
		var output bytes.Buffer
		var errOutput bytes.Buffer
		var runErr error
		if containsSensitiveInput(args) {
			close(progress)
			return commandResult{command: command, output: "Sensitive operations use the existing secure terminal prompt.\n", err: runInteractive(args)}
		}
		progressOutput := &progressWriter{dst: &output, channel: progress}
		runErr = m.options.Runner(args, strings.NewReader(""), progressOutput, &errOutput)
		progressOutput.flush()
		close(progress)
		if errOutput.Len() > 0 {
			output.WriteString(errOutput.String())
		}
		return commandResult{command: command, output: output.String(), err: runErr}
	}
	return tea.Batch(commandRun, waitForCommandProgress(progress))
}

func addSelectedSite(args []string, siteDir string) []string {
	if siteDir == "" || len(args) == 0 || args[0] == "init" || args[0] == "help" || args[0] == "tui" {
		return args
	}
	for _, arg := range args {
		if arg == "--site" || strings.HasPrefix(arg, "--site=") {
			return args
		}
	}
	result := append([]string(nil), args...)
	return append(result, "--site", siteDir)
}

func waitForCommandProgress(channel <-chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-channel
		if !ok {
			return commandProgress{channel: channel, done: true}
		}
		return commandProgress{channel: channel, line: line}
	}
}

type progressWriter struct {
	dst     io.Writer
	channel chan<- string
	partial string
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n == 0 {
		return n, err
	}
	w.partial += string(p[:n])
	for {
		index := strings.IndexByte(w.partial, '\n')
		if index < 0 {
			break
		}
		w.send(w.partial[:index])
		w.partial = w.partial[index+1:]
	}
	return n, err
}

func (w *progressWriter) flush() {
	if w.partial != "" {
		w.send(w.partial)
		w.partial = ""
	}
}

func (w *progressWriter) send(line string) {
	line = strings.TrimSpace(line)
	if !isProgressLine(line) {
		return
	}
	select {
	case w.channel <- line:
	default:
		// The completed command output remains authoritative. A bounded
		// TUI channel must not slow or break the underlying operation.
	}
}

func isProgressLine(line string) bool {
	return strings.HasPrefix(line, "[") ||
		strings.HasPrefix(line, "PASS ") ||
		strings.HasPrefix(line, "FAIL ") ||
		strings.HasPrefix(line, "FAIL:") ||
		strings.HasPrefix(line, "Changed:") ||
		strings.HasPrefix(line, "Timing:") ||
		strings.HasPrefix(line, "timing stage=") ||
		strings.HasPrefix(line, "Bootstrap:") ||
		strings.HasPrefix(line, "Deployment:") ||
		strings.HasPrefix(line, "Network test ") ||
		strings.HasPrefix(line, "Network cleanup:")
}

func (m *modelState) refresh() tea.Cmd {
	return func() tea.Msg {
		var output bytes.Buffer
		var errOutput bytes.Buffer
		err := m.options.Runner([]string{"status", "--site", m.options.SiteDir, "--live", "--json"}, strings.NewReader(""), &output, &errOutput)
		var report statusmodel.Report
		decodeErr := json.Unmarshal(output.Bytes(), &report)
		if decodeErr != nil {
			if err == nil {
				err = fmt.Errorf("decode live status: %w", decodeErr)
			}
		}
		var metrics *Observability
		if m.options.Observability != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			observed, metricsErr := m.options.Observability(ctx)
			cancel()
			if metricsErr != nil && err == nil {
				err = metricsErr
			} else if metricsErr == nil {
				metrics = &observed
			}
		}
		return refreshResult{report: report, output: output.String(), metrics: metrics, err: err}
	}
}

func (m *modelState) resize() {
	if m.width < 1 || m.height < 1 {
		return
	}
	left := min(38, max(28, m.width/3))
	m.commands.SetSize(left, max(8, m.height-8))
	m.input.SetWidth(max(20, m.width-left-8))
	m.viewport.SetWidth(max(20, m.width-left-8))
	m.viewport.SetHeight(max(5, m.height-10))
}

func (m *modelState) View() tea.View {
	left := m.commands.View()
	main := m.mainView()
	content := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(min(40, max(30, m.width/3))).Render(left),
		lipgloss.NewStyle().PaddingLeft(1).Width(max(20, m.width-min(40, max(30, m.width/3))-2)).Render(main),
	)
	view := tea.NewView(content + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("c commands  d dashboard  r refresh  esc back  q quit"))
	view.AltScreen = true
	return view
}

func (m *modelState) mainView() string {
	if m.width == 0 {
		return "Loading Boetticher..."
	}
	if m.mode == argumentMode {
		if m.running {
			body := "Working..."
			if len(m.progressLines) > 0 {
				body += "\n\n" + strings.Join(m.progressLines, "\n")
			} else {
				body += "\nWaiting for the first progress update..."
			}
			return panel(m.command, body)
		}
		return panel("Run command", m.input.View()+"\n\nEnter to run · esc to cancel")
	}
	if m.mode == outputMode {
		return panel(m.command, m.viewport.View())
	}

	s := m.snapshot
	title := "BOETTICHER"
	domain := "site unavailable"
	gateway := "unknown gateway"
	guests, modules, zones := 0, 0, 0
	if s.loadError == nil {
		domain = s.site.Network.Domain
		gateway = s.site.Gateway.Mode
		guests = len(s.site.Components)
		modules = len(s.site.Modules)
		zones = len(s.site.Network.Zones)
	}
	result := "FAIL"
	if s.report.OverallState == statusmodel.Healthy {
		result = "PASS"
	}
	lines := []string{
		styleTitle.Render(title),
		styleMuted.Render("experimental operator console"),
		"",
		panel("Site", fmt.Sprintf("Domain      %s\nGateway     %s\nZones       %d\nManaged     %d guests\nModules     %d", domain, gateway, zones, guests, modules)),
		panel("Status", fmt.Sprintf("Platform    %s\nObserved    %s\nLoaded      %s", result, valueOrDash(s.report.ObservedAt), valueOrDash(s.loadedAt.Format(time.RFC3339)))),
	}
	if s.metrics != nil {
		lines = append(lines, panel("Pulse observability", fmt.Sprintf("Health      %s\nAlerts      %d active\nNodes       %d\nVMs         %d\nContainers  %d\nResources   %d\nUpdated     %s", s.metrics.Health, s.metrics.ActiveAlerts, s.metrics.Nodes, s.metrics.VMs, s.metrics.Containers, s.metrics.Resources, valueOrDash(s.metrics.LastUpdate))))
	}
	if s.loadError != nil {
		lines = append(lines, panel("FAIL", safeError(s.loadError)+"\nUse c → init to create or inspect a site."))
	}
	if s.liveOutput != "" && m.message != "" {
		lines = append(lines, styleMuted.Render(m.message))
	} else if m.message != "" {
		lines = append(lines, styleMuted.Render(m.message))
	}
	return strings.Join(lines, "\n")
}

func panel(title, body string) string {
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#5f5f87")).Padding(0, 1).MarginBottom(1).Render(stylePanelTitle.Render(title) + "\n" + body)
}

func loadSnapshot(dir string) snapshot {
	result := snapshot{loadedAt: time.Now().UTC()}
	s, err := site.Load(dir)
	if err != nil {
		result.loadError = fmt.Errorf("load site: %w", err)
		return result
	}
	result.site = s
	revision, err := s.Revision()
	if err != nil {
		result.loadError = fmt.Errorf("calculate model revision: %w", err)
		return result
	}
	data, err := pathguard.ReadFile(filepath.Join(dir, "generated", "status.json"))
	if err == nil {
		if json.Unmarshal(data, &result.report) != nil || result.report.StatusModelVersion != statusmodel.ModelVersion || result.report.ModelRevision != revision {
			result.report = desiredReport(s, revision)
		}
	} else {
		result.report = desiredReport(s, revision)
	}
	return result
}

func desiredReport(s model.Site, revision string) statusmodel.Report {
	checks := []statusmodel.LegacyCheck{{Name: "desired platform model", Status: "PASS", Detail: "typed desired state composed locally"}}
	for _, module := range s.Modules {
		status := "FAIL"
		detail := "live runtime evidence is unavailable in offline mode"
		if !module.Enabled {
			status = "PASS"
			detail = "module is disabled"
		}
		checks = append(checks, statusmodel.LegacyCheck{Name: module.Name, Status: status, Detail: detail})
	}
	return statusmodel.FromLegacy(revision, time.Now().UTC().Format(time.RFC3339), checks)
}

func commandPath(usage string) string {
	usage = strings.TrimPrefix(usage, "boetticher ")
	if index := strings.IndexByte(usage, '['); index >= 0 {
		usage = usage[:index]
	}
	return strings.TrimSpace(usage)
}

func containsSensitiveInput(args []string) bool {
	if len(args) >= 2 && args[0] == "module" && args[1] == "secrets" {
		return true
	}
	for _, arg := range args {
		if arg == "--secret" {
			return true
		}
	}
	return false
}

func runInteractive(args []string) error {
	command := exec.Command(os.Args[0], args...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func valueOrDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

var (
	styleTitle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F793FF"))
	stylePanelTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#AD58B4"))
	styleMuted      = lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
