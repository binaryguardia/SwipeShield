package agentclient

import (
	"os"
)

// Tailer follows a JSONL file (the local WAF's events.log), remembering its
// offset across ticks so each new line is forwarded exactly once. It tolerates
// log rotation by resetting when the file shrinks, and holds a partially
// written trailing line until the newline arrives so events are never lost.
type Tailer struct {
	path   string
	offset int64
}

// NewTailer returns a Tailer for path, positioned at the current end of the
// file so only newly-appended lines are streamed.
func NewTailer(path string) *Tailer {
	t := &Tailer{path: path}
	if st, err := os.Stat(path); err == nil {
		t.offset = st.Size()
	}
	return t
}

// Lines returns the new complete lines appended since the last call. A trailing
// line without a newline is held back until it completes.
func (t *Tailer) Lines() []string {
	f, err := os.Open(t.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() < t.offset {
		t.offset = 0 // rotation
	}
	if st.Size() == t.offset {
		return nil
	}
	buf := make([]byte, st.Size()-t.offset)
	if _, err := f.ReadAt(buf, t.offset); err != nil {
		return nil
	}
	var out []string
	start := 0
	hold := false
	for i := 0; i < len(buf); i++ {
		if buf[i] == '\n' {
			if i > start {
				out = append(out, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(buf) {
		// Trailing bytes with no newline: hold them for the next poll.
		hold = true
	}
	t.offset += int64(start)
	if !hold && start == len(buf) {
		t.offset = st.Size()
	}
	return out
}
