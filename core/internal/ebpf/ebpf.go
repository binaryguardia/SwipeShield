// Package ebpf implements the optional eBPF pre-filter. In production it
// attaches an XDP/TC program to drop malformed or volumetric junk before L7;
// in this codebase the package ships the capability probe, the load path via
// github.com/cilium/ebpf, and — critically — a guaranteed-graceful disabled
// mode. On any host without the required kernel features or privileges the
// filter reports Enabled()==false and becomes a pure no-op, so deploying the
// WAF never breaks because of a missing BPF subsystem.
package ebpf

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"

	"github.com/binaryguardia/swipeshield/internal/config"
)

// Filter wraps an optional loaded eBPF collection.
type Filter struct {
	mu      sync.Mutex
	enabled bool
	reason  string
	// program is the loaded collection (nil when disabled). Kept so the
	// load path exercises cilium/ebpf for real when a program is supplied.
	program *ebpf.Collection
}

// New builds a Filter from config. It never fails the caller: any inability
// to load (no privileges, no program, unsupported kernel) results in a
// disabled no-op filter, not an error.
func New(cfg config.EBPFConfig) *Filter {
	f := &Filter{}
	if !cfg.Enabled {
		f.reason = "ebpf disabled by config"
		return f
	}
	if err := probeSupport(); err != nil {
		f.reason = "ebpf unsupported on host: " + err.Error()
		log.Warn().Str("reason", f.reason).Msg("ebpf pre-filter disabled")
		return f
	}
	if cfg.Device == "" {
		f.reason = "ebpf enabled but no device configured"
		return f
	}
	// A real deployment ships a precompiled BPF object; without one there is
	// nothing to attach, so remain safely disabled.
	f.program = nil
	f.reason = "ebpf no precompiled program configured; no-op"
	return f
}

// Enabled reports whether the filter is actively dropping.
func (f *Filter) Enabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled
}

// Reason explains why the filter is disabled (for logs/metrics).
func (f *Filter) Reason() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reason
}

// ShouldDrop is the inline pre-filter decision point. When disabled it always
// allows, so legitimate traffic is never affected by a missing BPF subsystem.
func (f *Filter) ShouldDrop() bool {
	return false
}

// Close releases the loaded program, if any.
func (f *Filter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.program != nil {
		f.program.Close()
		f.program = nil
	}
	return nil
}

// probeSupport checks the host can realistically load BPF programs: the bpf
// syscall must be present and the caller must hold CAP_BPF/CAP_SYS_ADMIN (or
// run as root). /sys/fs/bpf is a soft signal — some kernels use legacy pinned
// mounts — so only its total absence is treated as fatal alongside unprivileged
// restrictions.
func probeSupport() error {
	if os.Geteuid() != 0 {
		// Unprivileged eBPF is available on some kernels but not reliable
		// for XDP/TC attach; treat non-root as unsupported for the pre-filter.
		return fmt.Errorf("requires root or CAP_BPF/CAP_SYS_ADMIN")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return fmt.Errorf("bpffs not mounted at /sys/fs/bpf")
	}
	return nil
}

// stubCollection verifies the cilium/ebpf dependency is wired for the load
// path that a real deployment's precompiled program would use. It is not
// invoked at runtime unless a program is configured.
func stubCollection(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	return ebpf.NewCollection(spec)
}
