package server

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/siyamsarker/WireShield/dashboard/config"
	"github.com/siyamsarker/WireShield/dashboard/internal/auth"
	"github.com/siyamsarker/WireShield/dashboard/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Server struct {
	cfg     *config.Config
	cfgPath string
	mux     *http.ServeMux
	sess    *auth.Manager
	wg      *wireguard.Service
	tmpls   *template.Template
}

func New(cfg *config.Config, cfgPath string) *Server {
	s := &Server{cfg: cfg, cfgPath: cfgPath, mux: http.NewServeMux(), sess: auth.New(cfg.SessionKey)}
	// locate script path
	script := os.Getenv("WIRE_SHIELD_SCRIPT")
	if script == "" {
		// default install path
		script = "/root/wireshield.sh"
		if _, err := os.Stat(script); os.IsNotExist(err) {
			script = "/usr/local/bin/wireshield.sh"
		}
	}
	s.wg = wireguard.NewService(script)

	// templates
	s.tmpls = template.Must(template.New("").ParseFS(templatesFS, "templates/*.tmpl"))

	// static files (embedded) - mount sub FS at 'static' so /static/* resolves
	if sub, err := fs.Sub(staticFS, "static"); err == nil {
		s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.withAuth(s.handleLogout))
	s.mux.HandleFunc("/", s.withAuth(s.handleHome))
	s.mux.HandleFunc("/clients", s.withAuth(s.handleClients))
	s.mux.HandleFunc("/clients/new", s.withAuth(s.handleAddClient))
	s.mux.HandleFunc("/clients/revoke", s.withAuth(s.handleRevokeClient))
	s.mux.HandleFunc("/clients/config", s.withAuth(s.handleClientConfig))
	s.mux.HandleFunc("/clients/qr", s.withAuth(s.handleClientQR))
	s.mux.HandleFunc("/clients/check-expired", s.withAuth(s.handleCheckExpired))
	s.mux.HandleFunc("/status", s.withAuth(s.handleStatus))
	s.mux.HandleFunc("/restart", s.withAuth(s.handleRestart))
	s.mux.HandleFunc("/backup", s.withAuth(s.handleBackup))
	s.mux.HandleFunc("/uninstall", s.withAuth(s.handleUninstall))
	s.mux.HandleFunc("/settings/password", s.withAuth(s.handlePassword))
}

func (s *Server) Start() error {
	return http.ListenAndServe(s.cfg.Listen, s.logRequests(s.mux))
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sess.CurrentUser(r); !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		h(w, r)
	}
}

// Handlers

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
			http.Error(w, "invalid CSRF", http.StatusForbidden)
			return
		}
		u := r.FormValue("username")
		p := r.FormValue("password")
		for _, a := range s.cfg.Admins {
			if a.Username == u && config.CheckPassword(a.PasswordHash, p) {
				s.sess.SetUser(w, u)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
		s.render(w, "login.tmpl", map[string]any{"Error": "Invalid credentials", "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	s.render(w, "login.tmpl", map[string]any{"CSRF": s.sess.EnsureCSRF(w, r)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sess.Clear(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	clients, _ := s.wg.ListClients()
	s.render(w, "clients.tmpl", map[string]any{"Clients": clients, "CSRF": s.sess.EnsureCSRF(w, r)})
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.wg.ListClients()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "clients.tmpl", map[string]any{"Clients": clients, "CSRF": s.sess.EnsureCSRF(w, r)})
}

func (s *Server) handleAddClient(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
			http.Error(w, "invalid CSRF", http.StatusForbidden)
			return
		}
		name := r.FormValue("name")
		daysStr := r.FormValue("days")
		days := 0
		if daysStr != "" {
			if v, err := strconv.Atoi(daysStr); err == nil {
				days = v
			}
		}
		res, err := s.wg.AddClient(name, days)
		if err != nil {
			s.render(w, "add_client.tmpl", map[string]any{"Error": err.Error(), "CSRF": s.sess.EnsureCSRF(w, r)})
			return
		}
		s.render(w, "add_client.tmpl", map[string]any{"Success": true, "Result": res, "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	s.render(w, "add_client.tmpl", map[string]any{"CSRF": s.sess.EnsureCSRF(w, r)})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF", http.StatusForbidden)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "missing name", 400)
		return
	}
	if err := s.wg.RevokeClient(name); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusFound)
}

func (s *Server) handleClientConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", 400)
		return
	}
	cfg, err := s.wg.GetClientConfig(name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(name)+".conf")
	_, _ = w.Write([]byte(cfg))
}

func (s *Server) handleClientQR(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", 400)
		return
	}
	cfgText, err := s.wg.GetClientConfig(name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	png, err := qrcode.Encode(cfgText, qrcode.Medium, 300)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(200)
	_, _ = w.Write(png)
}

func (s *Server) handleCheckExpired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF", http.StatusForbidden)
		return
	}
	if _, err := s.wg.CheckExpired(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusFound)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.wg.ShowStatus()
	if err != nil {
		w.WriteHeader(500)
	}
	s.render(w, "status.tmpl", map[string]any{"Output": out, "CSRF": s.sess.EnsureCSRF(w, r)})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF", http.StatusForbidden)
		return
	}
	if err := s.wg.Restart(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/status", http.StatusFound)
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF", http.StatusForbidden)
		return
	}
	path, err := s.wg.Backup()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "backup.tmpl", map[string]any{"Path": path})
}

func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF", http.StatusForbidden)
		return
	}
	if err := s.wg.Uninstall(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "uninstall.tmpl", nil)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sess.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		s.render(w, "password.tmpl", map[string]any{"CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.sess.VerifyCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF", http.StatusForbidden)
		return
	}
	old := r.FormValue("old_password")
	npw := r.FormValue("new_password")
	cpw := r.FormValue("confirm_password")
	if npw == "" || len(npw) < 8 {
		s.render(w, "password.tmpl", map[string]any{"Error": "New password must be at least 8 characters", "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	if npw != cpw {
		s.render(w, "password.tmpl", map[string]any{"Error": "Passwords do not match", "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	// find admin
	idx := -1
	for i, a := range s.cfg.Admins {
		if a.Username == user {
			idx = i
			break
		}
	}
	if idx < 0 {
		http.Error(w, "user not found", 404)
		return
	}
	if !config.CheckPassword(s.cfg.Admins[idx].PasswordHash, old) {
		s.render(w, "password.tmpl", map[string]any{"Error": "Current password is incorrect", "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	hash, err := config.HashPassword(npw)
	if err != nil {
		s.render(w, "password.tmpl", map[string]any{"Error": err.Error(), "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	s.cfg.Admins[idx].PasswordHash = hash
	if s.cfgPath == "" {
		http.Error(w, errors.New("config path not set").Error(), 500)
		return
	}
	if err := config.Save(s.cfgPath, s.cfg); err != nil {
		s.render(w, "password.tmpl", map[string]any{"Error": err.Error(), "CSRF": s.sess.EnsureCSRF(w, r)})
		return
	}
	s.render(w, "password.tmpl", map[string]any{"Success": true, "CSRF": s.sess.EnsureCSRF(w, r)})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	if err := s.tmpls.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
