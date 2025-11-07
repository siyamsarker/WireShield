package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the sqlite connection and provides helper methods
type DB struct {
	*sql.DB
	path string
}

// Open creates or opens the SQLite database at the specified path
func Open(dbPath string) (*DB, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite3", fmt.Sprintf("%s?_journal_mode=WAL&_timeout=5000&_foreign_keys=1", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	wrapper := &DB{DB: db, path: dbPath}

	// Initialize schema
	if err := wrapper.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	log.Printf("Database initialized at %s", dbPath)
	return wrapper, nil
}

// initSchema applies the database schema
func (db *DB) initSchema() error {
	_, err := db.Exec(Schema)
	return err
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}

// Path returns the database file path
func (db *DB) Path() string {
	return db.path
}

// Transaction helpers
type TxFunc func(*sql.Tx) error

// WithTransaction executes fn within a transaction
func (db *DB) WithTransaction(fn TxFunc) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Backup creates a backup of the database
func (db *DB) Backup(destPath string) error {
	// Use SQLite backup API through a custom query
	backupSQL := fmt.Sprintf("VACUUM INTO '%s'", destPath)
	_, err := db.Exec(backupSQL)
	return err
}
