package botscoring

import (
	"testing"
	"time"
)

func TestScoreBrowsersLow(t *testing.T) {
	s := NewScorer()
	score := s.Score(Signal{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		HasAccept: true,
		HasCookie: true,
	})
	if score > 0.2 {
		t.Fatalf("browser scored %.2f", score)
	}
}

func TestScoreBotsHigh(t *testing.T) {
	s := NewScorer()
	for _, ua := range []string{"curl/8.5.0", "python-requests/2.31", "sqlmap/1.8", "Go-http-client/1.1", "Wget/1.21", "Scrapy/2.11"} {
		score := s.Score(Signal{UserAgent: ua, HasAccept: false, HasCookie: false})
		if score < 0.4 {
			t.Fatalf("UA %q scored %.2f, expected high", ua, score)
		}
	}
}

func TestScoreBurstTraffic(t *testing.T) {
	s := NewScorer()
	score := s.Score(Signal{UserAgent: "Mozilla/5.0", HasAccept: true, HasCookie: true, RequestsPerMin: 500})
	if score < 0.25 {
		t.Fatalf("burst traffic scored %.2f", score)
	}
}

func TestScoreClampedToOne(t *testing.T) {
	s := NewScorer()
	score := s.Score(Signal{UserAgent: "curl/8.5.0 python-requests", HasAccept: false, HasCookie: false, RequestsPerMin: 99999})
	if score > 1 {
		t.Fatalf("score %f > 1", score)
	}
}

func TestChallengeVerify(t *testing.T) {
	c, err := NewChallenge(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	proof := solve(c, 1000000)
	if proof == "" {
		t.Fatal("no proof found")
	}
	if !c.Verify(proof) {
		t.Fatalf("generated proof not accepted: %q", proof)
	}
	if c.Verify(proof + "zz") {
		t.Fatal("tampered proof accepted")
	}
}

// solve brute-forces the nonce+proof hash until difficulty zero-nibbles match.
func solve(c *Challenge, max int) string {
	for i := 0; i < max; i++ {
		p := itoa(i)
		if c.Verify(p) {
			return p
		}
	}
	return ""
}

func itoa(i int) string {
	const digits = "0123456789abcdef"
	if i == 0 {
		return "0"
	}
	var b [16]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = digits[i&0xf]
		i >>= 4
	}
	return string(b[pos:])
}

func TestChallengeExpiry(t *testing.T) {
	c, _ := NewChallenge(1, -time.Second)
	if c.Verify("0") {
		t.Fatal("expired challenge accepted")
	}
}

func TestStoreRedeemOnce(t *testing.T) {
	st := NewStore(time.Minute)
	c, err := st.Issue(1)
	if err != nil {
		t.Fatal(err)
	}
	proof := solve(c, 100000)
	if !st.Redeem(c.ID, proof) {
		t.Fatal("redeem failed")
	}
	if st.Redeem(c.ID, proof) {
		t.Fatal("challenge redeemed twice")
	}
}
