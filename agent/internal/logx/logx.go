// Package logx is a minimal leveled-logging helper. We intentionally avoid
// bringing in zap/zerolog so the agent binary stays small and static. Output
// is plain stderr; systemd journal will add timestamps and tags.
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	mu    sync.Mutex
	out   io.Writer = os.Stderr
	level           = LevelInfo
)

func SetLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	level = l
}

func SetLevelFromEnv(v string) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		SetLevel(LevelDebug)
	case "info", "":
		SetLevel(LevelInfo)
	case "warn", "warning":
		SetLevel(LevelWarn)
	case "error":
		SetLevel(LevelError)
	}
}

func logf(l Level, tag, format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if l < level {
		return
	}
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(out, "%s %s %s\n", ts, tag, msg)
}

func Debug(format string, args ...any) { logf(LevelDebug, "DEBUG", format, args...) }
func Info(format string, args ...any)  { logf(LevelInfo, "INFO ", format, args...) }
func Warn(format string, args ...any)  { logf(LevelWarn, "WARN ", format, args...) }
func Error(format string, args ...any) { logf(LevelError, "ERROR", format, args...) }
