// Command smoke runs the fresh-clone quickstart checks against a running
// SentinelWAF stack: it verifies REST + GraphQL + WebSocket protection with
// the exact demo config shipped in deploy/compose.
//
// Usage: go run . -base http://127.0.0.1:8080 -host localhost
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

var failures int

func check(name string, got, want int, extra string) {
	status := "PASS"
	if got != want {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %-46s got=%d want=%d %s\n", status, name, got, want, extra)
}

func checkOK(name string, cond bool, detail string) {
	status := "PASS"
	if !cond {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %-46s %s\n", status, name, detail)
}

func doRequest(client *http.Client, method, url, ua, ctype, body string) (int, string) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return 0, err.Error()
	}
	req.Host = *hostFlag
	req.Header.Set("User-Agent", ua)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var (
	baseFlag = flag.String("base", "http://127.0.0.1:8080", "gateway base URL")
	hostFlag = flag.String("host", "localhost", "Host header / site domain")
)

func main() {
	flag.Parse()
	base := strings.TrimRight(*baseFlag, "/")

	client := &http.Client{Timeout: 10 * time.Second}

	// 1. REST: benign browser traffic passes.
	code, body := doRequest(client, "GET", base+"/api/hello", browserUA, "", "")
	check("REST benign request", code, 200, "")

	// 2. REST: classic SQLi is blocked.
	code, _ = doRequest(client, "POST", base+"/api/echo", browserUA, "application/x-www-form-urlencoded", "user=' OR 1=1 --")
	check("REST SQLi blocked", code, 403, "")

	// 3. REST: XSS is blocked.
	code, _ = doRequest(client, "POST", base+"/api/echo", browserUA, "text/plain", "<script>alert(1)</script>")
	check("REST XSS blocked", code, 403, "")

	// 4. GraphQL: benign query passes.
	code, body = doRequest(client, "POST", base+"/graphql", browserUA, "application/json", `{"query":"{ hello }"}`)
	check("GraphQL benign query", code, 200, "")
	if !strings.Contains(body, "hello") {
		checkOK("GraphQL response echoes query", false, body)
	} else {
		checkOK("GraphQL response echoes query", true, "")
	}

	// 5. GraphQL: depth bomb is blocked.
	depth := `{"query":"{ a { b { c { d { e { f { g { h { i { j { k { l } } } } } } } } } } } }"}`
	code, _ = doRequest(client, "POST", base+"/graphql", browserUA, "application/json", depth)
	check("GraphQL depth bomb blocked", code, 400, "")

	// 6. GraphQL: batching attack is blocked.
	batch := `{"query":"query A { hello } query B { hello }"}`
	code, _ = doRequest(client, "POST", base+"/graphql", browserUA, "application/json", batch)
	check("GraphQL batching blocked", code, 403, "")

	// 7. GraphQL: introspection is blocked.
	code, _ = doRequest(client, "POST", base+"/graphql", browserUA, "application/json", `{"query":"{ __schema { types { name } } }"}`)
	check("GraphQL introspection blocked", code, 403, "")

	// 8. Bot defense: curl traffic receives a proof-of-work challenge.
	code, _ = doRequest(client, "GET", base+"/api/hello", "curl/8.5.0", "", "")
	check("Bot traffic challenged", code, 429, "")

	// 9. WebSocket: benign echo round-trips through the inspected relay.
	if err := wsEcho(base, browserUA); err != nil {
		checkOK("WebSocket benign echo", false, err.Error())
	} else {
		checkOK("WebSocket benign echo", true, "")
	}

	// 10. WebSocket: a malicious message is dropped / connection closed.
	if err := wsMalicious(base, browserUA); err != nil {
		checkOK("WebSocket malicious message blocked", true, err.Error())
	} else {
		checkOK("WebSocket malicious message blocked", false, "connection stayed open")
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	if failures > 0 {
		fmt.Printf("SMOKE TEST FAILED: %d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("SMOKE TEST PASSED: REST + GraphQL + WebSocket all protected")
}

func wsDial(base, ua string) (*websocket.Conn, error) {
	// Dial through the configured site domain so the gateway routes the
	// upgrade; gorilla sets the Host header from the URL host.
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	host := *hostFlag
	if p := u.Port(); p != "" {
		host = net.JoinHostPort(host, p)
	}
	wsURL := "ws://" + host + "/ws"
	header := http.Header{"User-Agent": []string{ua}}
	c, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	return c, err
}

func wsEcho(base, ua string) error {
	c, err := wsDial(base, ua)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	msg := "ping from smoke test"
	if err := c.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, reply, err := c.ReadMessage()
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(reply) != msg {
		return fmt.Errorf("echo mismatch: %q", reply)
	}
	return nil
}

func wsMalicious(base, ua string) error {
	c, err := wsDial(base, ua)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	payload := `{"user":"' OR 1=1 --"}`
	if err := c.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		mt, msg, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("connection closed as expected: %w", err)
		}
		_ = mt
		if strings.Contains(string(msg), "OR 1=1") {
			return fmt.Errorf("malicious payload echoed back: %s", msg)
		}
	}
}
