package eventpipeline

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"time"
)

type httpClient struct {
	timeout time.Duration
}

func (c *httpClient) post(ctx context.Context, url string, body []byte) error {
	hc := &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sentinelwaf/1.0")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return &statusError{code: resp.StatusCode}
	}
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string {
	return "webhook returned " + http.StatusText(e.code)
}
