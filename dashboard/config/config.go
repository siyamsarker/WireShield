package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type AdminUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type Config struct {
	Listen     string      `json:"listen"`
	SessionKey string      `json:"session_key"`
	Admins     []AdminUser `json:"admins"`
}

func defaultConfig() *Config {
	return &Config{
		Listen:     "127.0.0.1:51821",
		SessionKey: randomKey(),
		Admins:     []AdminUser{},
	}
}

func randomKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		// create default if missing
		cfg := defaultConfig()
		if err := Save(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	cfg := &Config{}
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:51821"
	}
	if cfg.SessionKey == "" {
		cfg.SessionKey = randomKey()
	}
	return cfg, nil
}

func Save(path string, cfg *Config) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// InitConfig writes config with single admin user
func InitConfig(path, username, password string) error {
	if username == "" || password == "" {
		return errors.New("username/password required")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	cfg := defaultConfig()
	cfg.Admins = []AdminUser{{Username: username, PasswordHash: hash}}
	return Save(path, cfg)
}

// HashPassword returns a bcrypt hash of the password
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword compares a bcrypt hashed password with its possible plaintext equivalent
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}
