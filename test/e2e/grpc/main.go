// Command grpc runs end-to-end checks for SwipeShield's schema-aware gRPC
// field-level inspection against a running gateway (the compose stack).
//
// It sends real HTTP/2 (h2c) gRPC requests through the gateway to
// /greeter.Greeter/SayHello (schema in test/demoapp/proto/greeter.proto),
// encoding protobuf wire frames by hand:
//
//	benign     -> must pass inspection (not blocked)
//	sqli field -> 403 (blocked by CRS on the flattened field value)
//	xss field  -> 403
//	garbage    -> 400 (protobuf does not match schema)
//
// Usage: go run . -base http://127.0.0.1:8080 -host localhost
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

var (
	baseFlag = flag.String("base", "http://127.0.0.1:8080", "gateway base URL")
	hostFlag = flag.String("host", "localhost", "Host header / site domain")
)

var failures int

func check(name string, got, want int, extra string) {
	status := "PASS"
	if got != want {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %-44s got=%d want=%d %s\n", status, name, got, want, extra)
}

func checkOK(name string, cond bool, detail string) {
	status := "PASS"
	if !cond {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %-44s %s\n", status, name, detail)
}

// grpcFrame wraps a protobuf payload in a gRPC length-prefixed message frame
// (1 byte compression flag + 4 byte big-endian length).
func grpcFrame(payload []byte) []byte {
	out := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	return append(out, payload...)
}

// stringField encodes one proto3 string field: tag (field<<3|2), length, bytes.
func stringField(field int, v string) []byte {
	out := []byte{byte(field<<3) | 2, byte(len(v))}
	return append(out, v...)
}

func helloRequest(name, comment string) []byte {
	payload := stringField(1, name)
	payload = append(payload, stringField(2, comment)...)
	return grpcFrame(payload)
}

func send(client *http.Client, path string, body []byte) (int, string) {
	req, err := http.NewRequest(http.MethodPost, *baseFlag+path, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Host = *hostFlag
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func main() {
	flag.Parse()

	// HTTP/2 cleartext (h2c) client — the gateway's plain listener negotiates
	// HTTP/2 via prior knowledge.
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	path := "/greeter.Greeter/SayHello"

	// 1. Benign fields pass inspection (backend is a plain HTTP app, so a
	//    non-403 status proves the request was not blocked).
	code, _ := send(client, path, helloRequest("alice", "all good here"))
	checkOK("gRPC benign request not blocked", code != 403, fmt.Sprintf("got=%d", code))

	// 2. SQLi inside a protobuf string field is blocked by CRS.
	code, body := send(client, path, helloRequest("bob", "' OR 1=1 --"))
	check("gRPC SQLi field blocked", code, 403, body)

	// 3. XSS inside a protobuf string field is blocked.
	code, _ = send(client, path, helloRequest("<script>alert(1)</script>", "fine"))
	check("gRPC XSS field blocked", code, 403, "")

	// 4. Garbage protobuf is rejected as malformed.
	code, _ = send(client, path, grpcFrame([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xBE}))
	check("gRPC malformed payload rejected", code, 400, "")

	fmt.Println("============================================================")
	if failures > 0 {
		fmt.Printf("GRPC TEST FAILED: %d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("GRPC TEST PASSED: schema-aware field inspection works")
}
