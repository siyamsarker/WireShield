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
	cookie := &http.Cookie{Name: m.cookie, Value: m.Sign(payload), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: true}
	// NOTE: set Secure=true when behind TLS terminator
	http.SetCookie(w, cookie)
}

func (m *Manager) Clear(w http.ResponseWriter) {
	cookie := &http.Cookie{Name: m.cookie, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: true}
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
	// Enforce expiry
	tsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	if t, err := time.Parse(time.RFC3339, string(tsRaw)); err == nil {
		if time.Now().After(t) {
			return "", false
		}
	}
	return parts[0], true
}

// CSRF support: stateless token signed in a non-HttpOnly cookie
const csrfCookie = "ws_csrf"

// EnsureCSRF sets a signed CSRF cookie if missing and returns the raw token value
func (m *Manager) EnsureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil {
		if v, ok := m.Verify(c.Value); ok {
			return v
		}
	}
	// create a token using timestamp (sufficient with HMAC signing)
	v := time.Now().Format(time.RFC3339Nano)
	signed := m.Sign(v)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: signed, Path: "/", HttpOnly: false, SameSite: http.SameSiteStrictMode, Secure: true})
	return v
}

// VerifyCSRF validates the posted token against the signed cookie
func (m *Manager) VerifyCSRF(r *http.Request, formValue string) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	v, ok := m.Verify(c.Value)
	if !ok {
		return false
	}
	return v == formValue && formValue != ""
}

// Flash messages: signed cookie carrying a small message to be shown once
const flashCookie = "ws_flash"

// SetFlash stores a one-time message (kind: success|error|info)
func (m *Manager) SetFlash(w http.ResponseWriter, kind, message string) {
	if message == "" {
		return
	}
	// payload: kind|base64(message)
	payload := kind + "|" + base64.RawURLEncoding.EncodeToString([]byte(message))
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: m.Sign(payload), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: true})
}

// PopFlash retrieves and clears the flash message
func (m *Manager) PopFlash(w http.ResponseWriter, r *http.Request) (kind, message string, ok bool) {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return "", "", false
	}
	val, okv := m.Verify(c.Value)
	// clear
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: true})
	if !okv {
		return "", "", false
	}
	parts := strings.SplitN(val, "|", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	msgBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return parts[0], "", true
	}
	return parts[0], string(msgBytes), true
}
