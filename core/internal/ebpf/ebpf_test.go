package ebpf

import (
	"testing"

	"github.com/binaryguardia/sentinelwaf/internal/config"
)

// TestDisabledNoOpOnUnsupportedHost is the core graceful-degradation
// guarantee: on a host without root / BPF support (i.e. CI), the filter is
// safely disabled and must never drop legitimate traffic or error.
func TestDisabledNoOpOnUnsupportedHost(t *testing.T) {
	cfg := config.EBPFConfig{Enabled: true, Device: "eth0", DropPort: 443}
	f := New(cfg)
	t.Cleanup(func() { _ = f.Close() })
	if f.Enabled() {
		t.Fatal("filter should be disabled without privileges/program")
	}
	if f.Reason() == "" {
		t.Fatal("disabled filter must record a reason")
	}
	if f.ShouldDrop() {
		t.Fatal("disabled filter must never drop")
	}
}

func TestDisabledByConfig(t *testing.T) {
	f := New(config.EBPFConfig{Enabled: false})
	if f.Enabled() {
		t.Fatal("config-disabled filter reported enabled")
	}
	if f.ShouldDrop() {
		t.Fatal("config-disabled filter dropped a request")
	}
}

func TestCloseIdempotent(t *testing.T) {
	f := New(config.EBPFConfig{Enabled: false})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal("second close must be a no-op")
	}
}

// BenchmarkDisabledShouldDrop measures the per-request cost of the disabled
// pre-filter — the mode that ships on hosts without BPF support. It must be
// negligible, proving "zero impact on legitimate traffic" from P17's DoD.
func BenchmarkDisabledShouldDrop(b *testing.B) {
	f := New(config.EBPFConfig{Enabled: false})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if f.ShouldDrop() {
			b.Fatal("disabled filter dropped")
		}
	}
}
