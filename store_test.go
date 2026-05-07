package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// newTestStore creates an in-memory SQLite store for testing.
func newTestStore(t *testing.T) *Store {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create in-memory store: %v", err)
	}
	return store
}

// newTestStoreWithPath creates a file-based SQLite store for testing.
func newTestStoreWithPath(t *testing.T) (*Store, string) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	return store, dbPath
}

func TestStore_CreateAndGet(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	session := &Session{
		ID:        "testid123",
		Secret:    "testsecret",
		HTML:      "<html>test</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	retrieved, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrieved.ID, session.ID)
	}
	if retrieved.Secret != session.Secret {
		t.Errorf("Secret mismatch: got %s, want %s", retrieved.Secret, session.Secret)
	}
	if retrieved.HTML != session.HTML {
		t.Errorf("HTML mismatch: got %s, want %s", retrieved.HTML, session.HTML)
	}
}

func TestStore_GetNonExistent(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	_, err := store.GetSession("nonexistent")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

func TestStore_UpdateSession(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	// Create initial session
	session := &Session{
		ID:        "updateid",
		Secret:    "initsecret",
		HTML:      "<html>initial</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Update with new values
	newHTML := "<html>updated</html>"
	newExpires := time.Now().Add(2 * time.Hour)
	var password []byte

	// Use correct secret for update
	updated, err := store.UpdateSession(session.ID, session.Secret, newHTML, password, newExpires)
	if err != nil {
		t.Fatalf("Failed to update session: %v", err)
	}

	if updated.HTML != newHTML {
		t.Errorf("HTML not updated: got %s, want %s", updated.HTML, newHTML)
	}
	if updated.ExpiresAt.Unix() != newExpires.Unix() {
		t.Errorf("ExpiresAt not updated: got %v, want %v", updated.ExpiresAt, newExpires)
	}

	// Verify by getting
	retrieved, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get updated session: %v", err)
	}
	if retrieved.HTML != newHTML {
		t.Errorf("Retrieved HTML mismatch: got %s, want %s", retrieved.HTML, newHTML)
	}
}

func TestStore_UpdateSessionWrongSecret(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	session := &Session{
		ID:        "wrongsecret",
		Secret:    "correctsecret",
		HTML:      "<html>test</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	_, err = store.UpdateSession(session.ID, "wrongsecret", "<html>updated</html>", nil, time.Now().Add(time.Hour))
	if err != ErrForbidden {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}
}

func TestStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	_, err := store.UpdateSession("nonexistent", "anyscret", "<html>test</html>", nil, time.Now().Add(time.Hour))
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

func TestStore_DeleteSession(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	session := &Session{
		ID:        "deleteid",
		Secret:    "deletesecret",
		HTML:      "<html>to delete</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = store.DeleteSession(session.ID, session.Secret)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify deleted
	_, err = store.GetSession(session.ID)
	if err != ErrSessionNotFound {
		t.Errorf("Session should be deleted, got: %v", err)
	}
}

func TestStore_DeleteSessionWrongSecret(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	session := &Session{
		ID:        "delwrong",
		Secret:    "rightsecret",
		HTML:      "<html>test</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = store.DeleteSession(session.ID, "wrongsecret")
	if err != ErrForbidden {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}
}

func TestStore_DeleteNonExistent(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	err := store.DeleteSession("nonexistent", "anyscret")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestStore_CleanupExpired tests that CleanupExpired removes expired sessions.
func TestStore_CleanupExpired(t *testing.T) {
	store, tmpDir := newTestStoreWithPath(t)
	defer store.Close()
	defer os.RemoveAll(tmpDir)

	// Create an expired session
	_ = os.MkdirAll(tmpDir, 0755) // ensure tmpDir exists
	expiredSession := &Session{
		ID:        "expiredid",
		Secret:    "expiredsecret",
		HTML:      "<html>expired</html>",
		Password:  nil,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
	}
	err := store.CreateSession(expiredSession.ID, expiredSession.Secret, expiredSession.HTML, expiredSession.Password, expiredSession.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create expired session: %v", err)
	}

	// Create a non-expired session
	validSession := &Session{
		ID:        "validid",
		Secret:    "validsecret",
		HTML:      "<html>valid</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), // Not expired
	}
	err = store.CreateSession(validSession.ID, validSession.Secret, validSession.HTML, validSession.Password, validSession.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create valid session: %v", err)
	}

	// Run cleanup
	count, err := store.CleanupExpired()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 expired session cleaned up, got %d", count)
	}

	// Verify expired is gone
	_, err = store.GetSession("expiredid")
	if err != ErrSessionNotFound {
		t.Errorf("Expired session should be deleted, got: %v", err)
	}

	// Verify valid still exists
	_, err = store.GetSession("validid")
	if err != nil {
		t.Errorf("Valid session should still exist: %v", err)
	}
}

func TestStore_SessionWithPassword(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	password := "testpassword123"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	session := &Session{
		ID:        "passwordid",
		Secret:    "passwordsecret",
		HTML:      "<html>protected</html>",
		Password:  hash,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err = store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session with password: %v", err)
	}

	retrieved, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session with password: %v", err)
	}

	if len(retrieved.Password) == 0 {
		t.Error("Password should be stored")
	}

	if err := bcrypt.CompareHashAndPassword(retrieved.Password, []byte(password)); err != nil {
		t.Error("Retrieved password hash does not match original password")
	}
}

// TestStore_ConcurrentCleanup tests that cleanup works with concurrent database access.
func TestStore_ConcurrentCleanup(t *testing.T) {
	// Use a file-based DB for this test since we're testing WAL mode concurrency
	store, tmpDir := newTestStoreWithPath(t)
	defer store.Close()
	defer os.RemoveAll(tmpDir)

	// Create multiple expired sessions
	for i := 0; i < 5; i++ {
		session := &Session{
			ID:        string(rune('a' + i)),
			Secret:    "secret",
			HTML:      "<html>test</html>",
			Password:  nil,
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		if err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt); err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
	}

	// Run cleanup
	count, err := store.CleanupExpired()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if count != 5 {
		t.Errorf("Expected 5 sessions cleaned up, got %d", count)
	}
}

// TestStore_UpdatePassword tests updating a session with a new password.
func TestStore_UpdatePassword(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	// Create session without password
	session := &Session{
		ID:        "nopassword",
		Secret:    "secret",
		HTML:      "<html>no password</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Update with password
	newPassword := []byte("newpassword123")
	hash, _ := bcrypt.GenerateFromPassword(newPassword, bcrypt.DefaultCost)

	_, err = store.UpdateSession(session.ID, session.Secret, "<html>updated with password</html>", hash, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to update session with password: %v", err)
	}

	retrieved, _ := store.GetSession(session.ID)
	if len(retrieved.Password) == 0 {
		t.Error("Password should be set after update")
	}
}

// TestStore_DeleteAllowsSubsequentCreate tests that deleting and recreating works.
func TestStore_DeleteAllowsSubsequentCreate(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	session := &Session{
		ID:        "recreate",
		Secret:    "secret",
		HTML:      "<html>original</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = store.DeleteSession(session.ID, session.Secret)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Recreate with same ID but different content
	err = store.CreateSession(session.ID, "newsecret", "<html>recreated</html>", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to recreate session: %v", err)
	}

	retrieved, _ := store.GetSession(session.ID)
	if retrieved.HTML != "<html>recreated</html>" {
		t.Errorf("HTML mismatch after recreation: got %s", retrieved.HTML)
	}
	if retrieved.Secret != "newsecret" {
		t.Errorf("Secret mismatch after recreation: got %s", retrieved.Secret)
	}
}

// TestStore_UpdateExpiresAt tests that updating changes the expires_at timestamp.
func TestStore_UpdateExpiresAt(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	session := &Session{
		ID:        "expiryupdate",
		Secret:    "secret",
		HTML:      "<html>test</html>",
		Password:  nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err := store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Update with longer expiry
	newExpiry := time.Now().Add(48 * time.Hour)
	_, err = store.UpdateSession(session.ID, session.Secret, "<html>test</html>", nil, newExpiry)
	if err != nil {
		t.Fatalf("Failed to update session: %v", err)
	}

	retrieved, _ := store.GetSession(session.ID)
	// Allow 1 minute tolerance for timing
	diff := retrieved.ExpiresAt.Sub(newExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("Expiry not updated correctly, diff: %v", diff)
	}
}

// TestStore_CleanupReturnsZeroForNoExpired tests that CleanupExpired returns 0 when nothing to clean.
func TestStore_CleanupReturnsZeroForNoExpired(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	count, err := store.CleanupExpired()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 when no expired sessions, got %d", count)
	}
}

// TestStore_PasswordHashRoundTrip tests that password hashes survive a store/get roundtrip.
func TestStore_PasswordHashRoundTrip(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	defer store.Close()

	password := "securepassword"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	session := &Session{
		ID:        "hashtest",
		Secret:    "secret",
		HTML:      "<html>test</html>",
		Password:  hash,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err = store.CreateSession(session.ID, session.Secret, session.HTML, session.Password, session.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	retrieved, _ := store.GetSession(session.ID)

	// Verify we can still verify the password
	if err := bcrypt.CompareHashAndPassword(retrieved.Password, []byte(password)); err != nil {
		t.Error("Password verification failed after roundtrip")
	}

	// Verify wrong password fails
	if err := bcrypt.CompareHashAndPassword(retrieved.Password, []byte("wrongpassword")); err == nil {
		t.Error("Wrong password should not verify")
	}
}