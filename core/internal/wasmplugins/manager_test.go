package wasmplugins

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// watPluginsDir contains prebuilt WAT plugins (fast.wasm, slow.wasm) built by
// wat-plugins/build.sh (or committed to the repo).
const watPluginsDir = "../../../wasm-plugins-examples/wat-plugins/dist"

func loadDist(t *testing.T, name string) *Manager {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(watPluginsDir, name))
	if err != nil {
		t.Skipf("%s not built; see wasm-plugins-examples/wat-plugins/build.sh", name)
	}
	m, err := NewManager(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load("testplugin", b); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExamplePluginVerdicts(t *testing.T) {
	m := loadDist(t, "fast.wasm")
	defer m.Close()

	vs, err := m.Evaluate(PluginRequest{
		Method: "POST", Path: "/api/exec", Host: "app.example.com", ClientIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawBlock bool
	for _, v := range vs {
		if v.RuleID == "WASM-WAT-001" && v.Action == "block" {
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Fatalf("expected WASM-WAT-001 block verdict, got %+v", vs)
	}
}

func TestSlowPluginKilledByTimeout(t *testing.T) {
	m := loadDist(t, "slow.wasm")
	m.opts.Timeout = 400 * time.Millisecond
	defer m.Close()

	start := time.Now()
	_, err := m.Evaluate(PluginRequest{Method: "GET", Path: "/"})
	if err == nil {
		t.Fatal("expected timeout error for busy-loop plugin")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout enforcement too slow: %s", time.Since(start))
	}
}

func TestPluginInvalidOutput(t *testing.T) {
	m, err := NewManager(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Load("garbage", []byte("this is not wasm")); err != nil {
		t.Fatal(err)
	}
	_, err = m.Evaluate(PluginRequest{})
	if err == nil {
		t.Fatal("expected error for invalid wasm")
	}
}
