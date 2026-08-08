package agentclient

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendLines(t *testing.T, path string, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

func TestTailerStartsAtEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	write(t, path, "old-line\n")
	tr := NewTailer(path)
	if got := tr.Lines(); len(got) != 0 {
		t.Fatalf("expected no pre-existing lines, got %v", got)
	}
	appendLines(t, path, "new-line\n")
	if got := tr.Lines(); len(got) != 1 || got[0] != "new-line" {
		t.Fatalf("expected [new-line], got %v", got)
	}
}

func TestTailerPartialLineHeldUntilNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	write(t, path, "")
	tr := NewTailer(path)
	appendLines(t, path, "partial-no-newline")
	if got := tr.Lines(); len(got) != 0 {
		t.Fatalf("partial line should be held, got %v", got)
	}
	appendLines(t, path, "-completed\n")
	if got := tr.Lines(); len(got) != 1 || got[0] != "partial-no-newline-completed" {
		t.Fatalf("expected the completed line, got %v", got)
	}
}

func TestTailerNoDuplicateAfterEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	write(t, path, "")
	tr := NewTailer(path)
	appendLines(t, path, "a\nb\n")
	if got := tr.Lines(); len(got) != 2 {
		t.Fatalf("expected 2 lines, got %v", got)
	}
	if got := tr.Lines(); len(got) != 0 {
		t.Fatalf("no new data should yield no lines, got %v", got)
	}
}
