// Package wasmplugins implements the WASM plugin host for SwipeShield.
//
// Plugin ABI: a plugin is a WASI command module (any language that compiles
// to WASI — Go, Rust, C, AssemblyScript, TinyGo). The host passes a JSON
// request on stdin and reads a JSON verdict on stdout, always under a hard
// per-plugin execution timeout and a bounded memory budget enforced by the
// wazero host — a misbehaving or malicious plugin cannot stall the request
// path or exhaust host memory. Plugins never get raw filesystem/network
// access: only stdin/stdout/stderr are exposed.
package wasmplugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Action mirrors decision actions inside the plugin ABI.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
)

// PluginVerdict is a single verdict a plugin returns.
type PluginVerdict struct {
	RuleID  string  `json:"rule_id"`
	Message string  `json:"message"`
	Action  Action  `json:"action"` // block | challenge | log | allow
	Score   float64 `json:"score"`  // 0..1 severity
}

// PluginResponse is the stdout contract.
type PluginResponse struct {
	Verdicts []PluginVerdict `json:"verdicts"`
}

// PluginRequest is the stdin contract.
type PluginRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Host     string            `json:"host"`
	ClientIP string            `json:"client_ip"`
	Protocol string            `json:"protocol"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	SiteID   string            `json:"site_id"`
}

// Options configures the plugin host.
type Options struct {
	Dir       string
	Timeout   time.Duration
	MaxMemory uint64 // bytes
}

// Manager loads and executes WASI plugins.
type Manager struct {
	opts    Options
	mu      sync.RWMutex
	modules map[string][]byte // name -> wasm bytes
	runtime wazero.Runtime
	ctx     context.Context
}

// NewManager loads all .wasm files under Dir.
func NewManager(opts Options) (*Manager, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 100 * time.Millisecond
	}
	if opts.MaxMemory == 0 {
		opts.MaxMemory = 32 << 20
	}
	m := &Manager{
		opts:    opts,
		modules: map[string][]byte{},
		ctx:     context.Background(),
	}
	rtCfg := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(uint32(opts.MaxMemory/65536) + 1).
		WithCloseOnContextDone(true)
	rt := wazero.NewRuntimeWithConfig(m.ctx, rtCfg)
	if _, err := wasi_snapshot_preview1.Instantiate(m.ctx, rt); err != nil {
		return nil, err
	}
	m.runtime = rt
	if opts.Dir != "" {
		if err := m.LoadDir(opts.Dir); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// LoadDir loads every .wasm file in dir.
func (m *Manager) LoadDir(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".wasm") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			name := strings.TrimSuffix(d.Name(), ".wasm")
			if err := m.Load(name, b); err != nil {
				return fmt.Errorf("plugin %s: %w", name, err)
			}
		}
		return nil
	})
}

// Load registers a plugin by name.
func (m *Manager) Load(name string, wasm []byte) error {
	m.mu.Lock()
	m.modules[name] = wasm
	m.mu.Unlock()
	return nil
}

// Names returns the loaded plugin names.
func (m *Manager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for k := range m.modules {
		out = append(out, k)
	}
	return out
}

// Evaluate runs every plugin against a request. Execution is always
// time-bounded; a plugin that exceeds the deadline produces an error for
// that plugin and the others still run (fail-open per-plugin).
func (m *Manager) Evaluate(req PluginRequest) ([]PluginVerdict, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	names := make([]string, 0, len(m.modules))
	for n := range m.modules {
		names = append(names, n)
	}
	m.mu.RUnlock()

	var verdicts []PluginVerdict
	var firstErr error
	for _, name := range names {
		vs, err := m.runOne(name, in)
		if err != nil {
			// A single bad plugin must not silence the others: record the
			// error and keep going (fail-open per-plugin).
			if firstErr == nil {
				firstErr = fmt.Errorf("plugin %s: %w", name, err)
			}
			continue
		}
		verdicts = append(verdicts, vs...)
	}
	return verdicts, firstErr
}

func (m *Manager) runOne(name string, stdin []byte) ([]PluginVerdict, error) {
	m.mu.RLock()
	wasm, ok := m.modules[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("not loaded")
	}

	ctx, cancel := context.WithTimeout(m.ctx, m.opts.Timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cfg := wazero.NewModuleConfig().
		WithName("plugin-" + name).
		WithStdin(bytes.NewReader(stdin)).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithStartFunctions("_start")

	if _, err := m.runtime.InstantiateWithConfig(ctx, wasm, cfg); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("execution timeout (%s)", m.opts.Timeout)
		}
		return nil, err
	}

	var resp PluginResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("invalid plugin output: %w", err)
	}
	for i := range resp.Verdicts {
		if resp.Verdicts[i].Score < 0 {
			resp.Verdicts[i].Score = 0
		}
		if resp.Verdicts[i].Score > 1 {
			resp.Verdicts[i].Score = 1
		}
	}
	return resp.Verdicts, nil
}

// Close shuts down the runtime.
func (m *Manager) Close() error {
	return m.runtime.Close(m.ctx)
}
