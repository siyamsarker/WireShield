package server

import (
	"embed"
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
)

//go:embed templates/*.tmpl static/*
var uiFS embed.FS

type Server struct {
	cfg   *config.Config
	mux   *http.ServeMux
	sess  *auth.Manager
	wg    *wireguard.Service
	tmpls *template.Template
}

func New(cfg *config.Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux(), sess: auth.New(cfg.SessionKey)}
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
	s.tmpls = template.Must(template.New("").ParseFS(uiFS, "templates/*.tmpl"))

	// static files (embedded)
	if sub, err := fs.Sub(uiFS, "static"); err == nil {
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
	s.mux.HandleFunc("/clients/check-expired", s.withAuth(s.handleCheckExpired))
	s.mux.HandleFunc("/status", s.withAuth(s.handleStatus))
	s.mux.HandleFunc("/restart", s.withAuth(s.handleRestart))
	s.mux.HandleFunc("/backup", s.withAuth(s.handleBackup))
	s.mux.HandleFunc("/uninstall", s.withAuth(s.handleUninstall))
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
		u := r.FormValue("username")
		p := r.FormValue("password")
		for _, a := range s.cfg.Admins {
			if a.Username == u && config.CheckPassword(a.PasswordHash, p) {
				s.sess.SetUser(w, u)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
		s.render(w, "login.tmpl", map[string]any{"Error": "Invalid credentials"})
		return
	}
	s.render(w, "login.tmpl", nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sess.Clear(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	clients, _ := s.wg.ListClients()
	s.render(w, "clients.tmpl", map[string]any{"Clients": clients})
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.wg.ListClients()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "clients.tmpl", map[string]any{"Clients": clients})
}

func (s *Server) handleAddClient(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
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
			s.render(w, "add_client.tmpl", map[string]any{"Error": err.Error()})
			return
		}
		s.render(w, "add_client.tmpl", map[string]any{"Success": true, "Result": res})
		return
	}
	s.render(w, "add_client.tmpl", nil)
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
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

func (s *Server) handleCheckExpired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
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
	s.render(w, "status.tmpl", map[string]any{"Output": out})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
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
	if err := s.wg.Uninstall(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.render(w, "uninstall.tmpl", nil)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	if err := s.tmpls.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
