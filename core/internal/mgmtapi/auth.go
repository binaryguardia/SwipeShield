package mgmtapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// --- Password verification (argon2id) ---

// verifyPassword checks a password against a stored hash. It accepts an
// argon2id hash ("$argon2id$v=19$m=...,t=...,p=...$salt$hash") or — for local
// development only — a plaintext value.
func verifyPassword(password, stored string) bool {
	if stored == "" {
		return false
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		// Plaintext fallback (dev/test convenience).
		return password == stored
	}
	hash, salt, m, t, p, err := parseArgon2ID(stored)
	if err != nil {
		return false
	}
	candidate := argon2.IDKey([]byte(password), salt, t, m, uint8(p), uint32(len(hash)))
	return hmac.Equal(hash, candidate)
}

// HashPassword derives an argon2id hash with the given memory (KiB), time,
// parallelism, and key length (in bytes).
func HashPassword(password string, m, t, p uint32) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, t, m, uint8(p), 32)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		m, t, p,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func parseArgon2ID(encoded string) (hash, salt []byte, m, t, p uint32, err error) {
	parts := strings.Split(encoded, "$")
	// $argon2id$v=19$m=..,t=..,p=..$salt$hash
	if len(parts) != 6 {
		return nil, nil, 0, 0, 0, fmt.Errorf("malformed argon2id hash")
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return nil, nil, 0, 0, 0, fmt.Errorf("missing version")
	}
	params := parts[3]
	m = parseParam(params, "m")
	t = parseParam(params, "t")
	p = parseParam(params, "p")
	if m == 0 || t == 0 || p == 0 {
		return nil, nil, 0, 0, 0, fmt.Errorf("invalid params")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	return hash, salt, m, t, p, nil
}

func parseParam(s, key string) uint32 {
	for _, kv := range strings.Split(s, ",") {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			n, err := strconv.ParseUint(v, 10, 32)
			if err == nil {
				return uint32(n)
			}
		}
	}
	return 0
}

// --- JWT (HS256) ---

type claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func issueJWT(secret, sub string, ttl time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("jwt secret not configured")
	}
	now := time.Now()
	c, err := json.Marshal(claims{Sub: sub, Iat: now.Unix(), Exp: now.Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	header := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := b64(c)
	sig := hmacSHA256(secret, header+"."+payload)
	return header + "." + payload + "." + sig, nil
}

func verifyJWT(secret, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed token")
	}
	want := hmacSHA256(secret, parts[0]+"."+parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return "", fmt.Errorf("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", err
	}
	if c.Exp < time.Now().Unix() {
		return "", fmt.Errorf("token expired")
	}
	return c.Sub, nil
}

func hmacSHA256(secret, data string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(data))
	return b64(m.Sum(nil))
}
