package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

type Manager struct {
	secret []byte
	cookie string
}

func New(secret string) *Manager {
	return &Manager{secret: []byte(secret), cookie: "ws_session"}
}

func (m *Manager) Sign(value string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(value))
	mac := h.Sum(nil)
	return value + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func (m *Manager) Verify(signed string) (string, bool) {
	parts := strings.Split(signed, ".")
	if len(parts) < 2 {
		return "", false
	}
	value := strings.Join(parts[:len(parts)-1], ".")
	expMac, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return "", false
	}
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(value))
	if !hmac.Equal(expMac, h.Sum(nil)) {
		return "", false
	}
	return value, true
}

func (m *Manager) SetUser(w http.ResponseWriter, username string) {
	// simple payload: username|expiryUnix
	exp := time.Now().Add(24 * time.Hour).Unix()
	payload := username + "|" + base64.RawURLEncoding.EncodeToString([]byte(time.Unix(exp, 0).Format(time.RFC3339)))
	cookie := &http.Cookie{Name: m.cookie, Value: m.Sign(payload), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: false}
	// NOTE: set Secure=true when behind TLS terminator
	http.SetCookie(w, cookie)
}

func (m *Manager) Clear(w http.ResponseWriter) {
	cookie := &http.Cookie{Name: m.cookie, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	http.SetCookie(w, cookie)
}

func (m *Manager) CurrentUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(m.cookie)
	if err != nil {
		return "", false
	}
	val, ok := m.Verify(c.Value)
	if !ok {
		return "", false
	}
	parts := strings.SplitN(val, "|", 2)
	if len(parts) != 2 {
		return "", false
	}
	return parts[0], true
}
