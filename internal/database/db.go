package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB is a wrapper around sql.DB that provides WireShield-specific database operations.
// It includes connection pooling, WAL mode, and foreign key enforcement for data integrity.
type DB struct {
	*sql.DB        // Embedded SQLite connection handle
	path    string // Absolute path to the database file
}

// Open initializes a new SQLite database connection with production-ready settings.
// It configures WAL mode for concurrent access, connection pooling for performance,
// and automatically creates the schema if this is a new database.
//
// Parameters:
//   - dbPath: Absolute path where the database file should be stored
//
// Returns:
//   - *DB: Configured database wrapper ready for use
//   - error: Any errors during connection setup or schema initialization
func Open(dbPath string) (*DB, error) {
	// Create parent directory if it doesn't exist (e.g., /var/lib/wireshield/)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// Open SQLite with performance and safety optimizations:
	// - WAL mode: Allows concurrent reads during writes
	// - 5 second timeout: Prevents indefinite blocking on busy database
	// - Foreign keys ON: Enforces referential integrity
	db, err := sql.Open("sqlite3", fmt.Sprintf("%s?_journal_mode=WAL&_timeout=5000&_foreign_keys=1", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance:
	// - Max 25 connections: Handles high concurrent load
	// - 10 idle connections: Reduces latency for frequent queries
	// - 5 minute lifetime: Prevents stale connections
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify database is accessible before proceeding
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	wrapper := &DB{DB: db, path: dbPath}

	// Create all tables and indexes if they don't exist
	if err := wrapper.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	log.Printf("Database initialized at %s", dbPath)
	return wrapper, nil
}

// initSchema executes the SQL schema to create all tables and indexes.
// This is idempotent - safe to run multiple times without side effects.
func (db *DB) initSchema() error {
	_, err := db.Exec(Schema)
	return err
}

// Close gracefully shuts down the database connection and releases resources.
// Should be called with defer after opening the database.
func (db *DB) Close() error {
	return db.DB.Close()
}

// Path returns the absolute filesystem path to the database file.
// Useful for backup operations and diagnostics.
func (db *DB) Path() string {
	return db.path
}

// TxFunc is a function type that performs operations within a database transaction.
// It receives a transaction handle and returns an error if the operation fails.
type TxFunc func(*sql.Tx) error

// WithTransaction executes a function within a database transaction.
// It automatically handles commit on success or rollback on error/panic.
// This provides ACID guarantees for multi-statement operations.
//
// Parameters:
//   - fn: Function containing database operations to execute atomically
//
// Returns:
//   - error: nil on successful commit, or the error that caused rollback
//
// Example:
//
//	err := db.WithTransaction(func(tx *sql.Tx) error {
//	    _, err := tx.Exec("UPDATE clients SET enabled = 0 WHERE id = ?", clientID)
//	    return err
//	})
func (db *DB) WithTransaction(fn TxFunc) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Ensure rollback on panic to maintain database consistency
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-panic after rollback
		}
	}()

	// Execute the user's transaction function
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	// Commit if everything succeeded
	return tx.Commit()
}

// Backup creates an atomic backup of the database to the specified path.
// Uses SQLite's VACUUM INTO command which provides a consistent snapshot
// without locking the database for extended periods.
//
// Parameters:
//   - destPath: Absolute path where backup file should be created
//
// Returns:
//   - error: nil on success, or validation/filesystem errors
//
// Security:
//   - Validates path to prevent SQL injection
//   - Sanitizes path with filepath.Clean()
//   - Creates parent directories automatically
func (db *DB) Backup(destPath string) error {
	// Validate path to prevent SQL injection attacks
	// Block paths containing SQL metacharacters or empty paths
	if destPath == "" || strings.Contains(destPath, "'") || strings.Contains(destPath, ";") {
		return fmt.Errorf("invalid backup path")
	}

	// Ensure backup directory exists (e.g., /var/backups/wireshield/)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// VACUUM INTO creates a clean, compacted copy of the entire database
	// This is safer than file-level copying which could catch mid-transaction state
	backupSQL := fmt.Sprintf("VACUUM INTO '%s'", filepath.Clean(destPath))
	_, err := db.Exec(backupSQL)
	return err
}
