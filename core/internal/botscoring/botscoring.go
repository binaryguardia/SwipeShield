// Package botscoring computes a bot-likelihood score from fingerprint,
// behavioral and request-shape signals, and issues a self-hosted
// proof-of-work challenge for medium-confidence bot traffic instead of a
// hard block (no third-party CAPTCHA dependency).
package botscoring

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scorer combines signals into a 0..1 bot-likelihood score.
type Scorer struct {
	knownBots []*regexp.Regexp
	mu        sync.RWMutex
}

// NewScorer builds a scorer with built-in automation heuristics.
func NewScorer() *Scorer {
	patterns := []string{
		`(?i)python-requests`,
		`(?i)curl/`,
		`(?i)wget/`,
		`(?i)libwww-perl`,
		`(?i)scrapy`,
		`(?i)go-http-client`,
		`(?i)java/`,
		`(?i)okhttp`,
		`(?i)httpx/`,
		`(?i)sqlmap`,
		`(?i)nmap`,
		`(?i)masscan`,
		`(?i)headlesschrome`,
		`(?i)phantomjs`,
		`(?i)selenium`,
		`(?i)bot\b`,
		`(?i)crawler`,
		`(?i)spider`,
	}
	s := &Scorer{}
	for _, p := range patterns {
		s.knownBots = append(s.knownBots, regexp.MustCompile(p))
	}
	return s
}

// Signal bundles inputs for scoring.
type Signal struct {
	ClientIP  string
	JA4       string
	H2FP      string
	UserAgent string
	Method    string
	HasAccept bool
	HasCookie bool
	// RequestsPerMin is a behavioral signal from the rate limiter.
	RequestsPerMin int
}

// Score returns the bot-likelihood in [0,1].
func (s *Scorer) Score(sig Signal) float64 {
	score := 0.0

	ua := strings.TrimSpace(sig.UserAgent)
	if ua == "" {
		score += 0.2 // missing UA is suspicious for browsers
	}
	for _, re := range s.knownBots {
		if re.MatchString(ua) {
			score += 0.55
			break
		}
	}
	if !sig.HasAccept && ua != "" {
		score += 0.1
	}
	if !sig.HasCookie {
		score += 0.05 // fresh, non-browser clients often skip cookies
	}
	if sig.JA4 != "" {
		// JA4 is a strong signal; a fingerprint present and non-browser
		// can't be judged here without a reference DB, but absence of UA
		// alongside a raw TLS client is already weighted above.
	}
	if sig.RequestsPerMin > 120 {
		score += 0.25
	} else if sig.RequestsPerMin > 60 {
		score += 0.1
	}
	if score > 1 {
		score = 1
	}
	return score
}

// Challenge is a self-hosted proof-of-work.
type Challenge struct {
	ID         string    `json:"id"`
	Nonce      string    `json:"nonce"`
	Difficulty int       `json:"difficulty"` // required leading zero hex nibbles
	Expires    time.Time `json:"expires"`
}

// NewChallenge creates a challenge expiring in ttl.
func NewChallenge(difficulty int, ttl time.Duration) (*Challenge, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Challenge{
		ID:         hex.EncodeToString(b)[:16],
		Nonce:      hex.EncodeToString(b),
		Difficulty: difficulty,
		Expires:    time.Now().Add(ttl),
	}, nil
}

// Verify checks a proof: SHA256(nonce + proof) must start with
// `difficulty` zero hex nibbles.
func (c *Challenge) Verify(proof string) bool {
	if proof == "" || c.Difficulty <= 0 || time.Now().After(c.Expires) {
		return false
	}
	sum := sha256.Sum256([]byte(c.Nonce + proof))
	h := hex.EncodeToString(sum[:])
	return strings.HasPrefix(h, strings.Repeat("0", c.Difficulty))
}

// HTML returns a self-contained challenge page that solves the PoW in JS.
func (c *Challenge) HTML(action string) string {
	tpl := `<!doctype html><html><head><meta charset="utf-8">
<title>Verifying you are human</title>
<style>body{font-family:Inter,sans-serif;background:#0A0E14;color:#E6E9EF;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#131822;border:1px solid #2A3242;border-radius:12px;padding:32px;text-align:center;max-width:360px}
.spinner{width:28px;height:28px;border:3px solid #2A3242;border-top-color:#22D3EE;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><div class="card">
<div class="spinner"></div><h3>Checking your browser...</h3>
<p style="color:#8A93A6;font-size:13px">This site protects itself with a proof-of-work challenge.</p>
</div>
<script>
(function(){
  var nonce = "__NONCE__";
  var difficulty = __DIFF__;
  var deadline = Date.now() + 5000;
  function sha256hex(ascii){
    function rightRotate(v,a){return (v>>>a)|(v<<(32-a));}
    var mathPow=Math.pow, maxWord=mathPow(2,32), lengthProperty='length', i, j, result='';
    var words=[], asciiBitLength=ascii[lengthProperty]*8;
    var hash=sha256.h=sha256.h||[], k=sha256.k=sha256.k||[];
    var primeCounter=k[lengthProperty];
    var isComposite={};
    for(var candidate=2;primeCounter<64;candidate++){
      if(!isComposite[candidate]){for(i=0;i<313;i+=candidate){isComposite[i]=candidate;}hash[primeCounter]=mathPow(candidate,.5)*maxWord|0;k[primeCounter++]=mathPow(candidate,1/3)*maxWord|0;}}
    ascii+='\x80';
    while(ascii[lengthProperty]%64-56)ascii+='\x00';
    for(i=0;i<ascii[lengthProperty];i++){j=ascii.charCodeAt(i);words[i>>2]|=j<<((3-i)%4)*8;}
    words[words[lengthProperty]]=(asciiBitLength/maxWord)|0;words[words[lengthProperty]]=(asciiBitLength);
    for(j=0;j<words[lengthProperty];){var w=words.slice(j,j+=16),oldHash=hash;hash=hash.slice(0,8);
      for(i=0;i<64;i++){var w15=w[i-15],w2=w[i-2];
        var a=hash[0],e=hash[4];var temp1=hash[7]+(rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25))+((e&hash[5])^((~e)&hash[6]))+k[i]+(w[i]=i<16?w[i]:(w[i-16]+(rightRotate(w15,7)^rightRotate(w15,18)^(w15>>>3))+w[i-7]+(rightRotate(w2,17)^rightRotate(w2,19)^(w2>>>10)))|0);
        var temp2=(rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22))+((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));
        hash=[(temp1+temp2)|0,hash[0],hash[1],hash[2],hash[3]+temp1|0,hash[4],hash[5],hash[6]];
      }
      for(i=0;i<8;i++){hash[i]=hash[i]+oldHash[i]|0;}
    }
    for(i=0;i<8;i++){for(j=3;j+1;j--){var b=(hash[i]>>j*8)&255;result+=((b<16)?0:'')+b.toString(16);}}
    return result;
  }
  function solve(){
    for(var counter=0;;counter++){
      var proof = counter.toString(16);
      var h = sha256hex(nonce + proof);
      var ok = true;
      for(var i=0;i<difficulty;i++){ if(h[i]!=='0'){ok=false;break;} }
      if(ok){
        var form=document.createElement('form');form.method='POST';form.action='__ACTION__';
        var hidden=document.createElement('input');hidden.type='hidden';hidden.name='_pow';hidden.value=proof;
        form.appendChild(hidden);document.body.appendChild(form);form.submit();
        return;
      }
      if(Date.now()>deadline+2000){ location.reload(); return; }
    }
  }
  setTimeout(solve, 10);
})();
</script></body></html>`
	r := strings.NewReplacer("__NONCE__", c.Nonce, "__DIFF__", strconv.Itoa(c.Difficulty), "__ACTION__", action)
	return r.Replace(tpl)
}

// Store tracks issued and redeemed challenges.
type Store struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
	ttl        time.Duration
}

// NewStore creates a challenge store.
func NewStore(ttl time.Duration) *Store {
	return &Store{mu: sync.Mutex{}, challenges: map[string]*Challenge{}, ttl: ttl}
}

// Issue creates and records a challenge.
func (s *Store) Issue(difficulty int) (*Challenge, error) {
	c, err := NewChallenge(difficulty, s.ttl)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.challenges[c.ID] = c
	s.mu.Unlock()
	return c, nil
}

// Redeem verifies a proof for a challenge ID and removes it.
func (s *Store) Redeem(id, proof string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return false
	}
	delete(s.challenges, id)
	return c.Verify(proof)
}

// Prune removes expired challenges.
func (s *Store) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.challenges {
		if time.Now().After(c.Expires) {
			delete(s.challenges, id)
		}
	}
}
