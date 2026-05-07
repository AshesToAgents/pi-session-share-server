package main

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// ErrSessionNotFound is returned when a session is not found or has expired.
var ErrSessionNotFound = errors.New("session not found or expired")

// ErrForbidden is returned when a secret doesn't match.
var ErrForbidden = errors.New("forbidden: secret mismatch")

// Session represents a shared pi session stored in the database.
type Session struct {
	ID        string
	Secret    string
	Password  []byte // bcrypt hash, nil if no password
	HTML      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store provides SQLite-backed session storage.
type Store struct {
	db *sql.DB
}

// NewStore opens a SQLite database and creates the schema if needed.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}

	// Create tables if they don't exist
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		id         TEXT PRIMARY KEY,
		secret     TEXT NOT NULL,
		password   TEXT,
		html       TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// CreateSession creates a new session in the database.
func (s *Store) CreateSession(id, secret, html string, password []byte, expiresAt time.Time) error {
	var passwordStr sql.NullString
	if len(password) > 0 {
		passwordStr = sql.NullString{String: string(password), Valid: true}
	}

	query := `
		INSERT INTO sessions (id, secret, password, html, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query, id, secret, passwordStr, html, expiresAt.Format(time.RFC3339))
	return err
}

// GetSession retrieves a session by ID if it exists and hasn't expired.
func (s *Store) GetSession(id string) (*Session, error) {
	query := `
		SELECT id, secret, password, html, created_at, expires_at
		FROM sessions
		WHERE id = ? AND expires_at > datetime('now')
	`
	row := s.db.QueryRow(query, id)

	var session Session
	var passwordStr sql.NullString
	var createdAtStr, expiresAtStr string

	err := row.Scan(&session.ID, &session.Secret, &passwordStr, &session.HTML, &createdAtStr, &expiresAtStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	if passwordStr.Valid {
		session.Password = []byte(passwordStr.String)
	}

	session.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	session.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)

	return &session, nil
}

// UpdateSession updates an existing session after verifying the secret.
func (s *Store) UpdateSession(id, secret, html string, password []byte, expiresAt time.Time) (*Session, error) {
	// First verify the secret matches
	session, err := s.GetSession(id)
	if err != nil {
		return nil, err
	}
	if session.Secret != secret {
		return nil, ErrForbidden
	}

	var passwordStr sql.NullString
	if len(password) > 0 {
		passwordStr = sql.NullString{String: string(password), Valid: true}
	}

	query := `
		UPDATE sessions
		SET html = ?, password = ?, expires_at = ?
		WHERE id = ? AND secret = ?
	`
	result, err := s.db.Exec(query, html, passwordStr, expiresAt.Format(time.RFC3339), id, secret)
	if err != nil {
		return nil, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, ErrSessionNotFound
	}

	return &Session{
		ID:        id,
		Secret:    secret,
		Password:  password,
		HTML:      html,
		CreatedAt: session.CreatedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// DeleteSession deletes a session after verifying the secret.
func (s *Store) DeleteSession(id, secret string) error {
	// First verify the session exists and secret matches
	session, err := s.GetSession(id)
	if err != nil {
		return err // ErrSessionNotFound
	}
	if session.Secret != secret {
		return ErrForbidden
	}

	query := `DELETE FROM sessions WHERE id = ? AND secret = ?`
	_, err = s.db.Exec(query, id, secret)
	return err
}

// CleanupExpired removes all expired sessions and returns the count of deleted sessions.
func (s *Store) CleanupExpired() (int, error) {
	query := `DELETE FROM sessions WHERE expires_at < datetime('now')`
	result, err := s.db.Exec(query)
	if err != nil {
		return 0, err
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(count), nil
}
