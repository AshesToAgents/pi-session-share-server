package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// cleanupTracker tracks when cleanup runs
var cleanupRunCount int32

// TestCleanup_ExpiresSessions tests that StartCleanup removes expired sessions.
func TestCleanup_ExpiresSessions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create an expired session
	expiredSession := &Session{
		ID:        "expired",
		Secret:    "secret",
		HTML:      "<html>expired</html>",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	if err := store.CreateSession(expiredSession.ID, expiredSession.Secret, expiredSession.HTML, expiredSession.ExpiresAt); err != nil {
		t.Fatalf("Failed to create expired session: %v", err)
	}

	// Create a valid session
	validSession := &Session{
		ID:        "valid",
		Secret:    "secret",
		HTML:      "<html>valid</html>",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), // Expires in 1 hour
	}
	if err := store.CreateSession(validSession.ID, validSession.Secret, validSession.HTML, validSession.ExpiresAt); err != nil {
		t.Fatalf("Failed to create valid session: %v", err)
	}

	// First verify the expired session exists before cleanup
	_, err = store.GetSession("expired")
	if err != nil {
		t.Fatal("Expired session should exist before cleanup")
	}

	// Run cleanup directly to test the functionality
	count, err := store.CleanupExpired()
	if err != nil {
		t.Fatalf("Direct cleanup failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 expired session cleaned up, got %d", count)
	}

	// Verify expired session is gone
	_, err = store.GetSession("expired")
	if err != ErrSessionNotFound {
		t.Error("Expired session should be removed by cleanup")
	}

	// Verify valid session still exists
	_, err = store.GetSession("valid")
	if err != nil {
		t.Error("Valid session should still exist")
	}

	store.Close()
}

// TestCleanup_StartsAndStops tests that StartCleanup runs and stops correctly.
func TestCleanup_StartsAndStops(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup with a reasonable interval
	StartCleanup(ctx, store, 20*time.Millisecond)

	// Give it time to run at least one cycle
	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for the goroutine to stop
	time.Sleep(50 * time.Millisecond)

	// Store should still be accessible
	_, err = store.GetSession("nonexistent")
	if err != ErrSessionNotFound {
		t.Errorf("Store should still be accessible after context cancel: %v", err)
	}

	store.Close()
}

// TestCleanup_GoroutineCleansExpired tests the cleanup goroutine cleans expired sessions.
func TestCleanup_GoroutineCleansExpired(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create expired sessions (created 2 hours ago, expired 1 hour ago)
	for i := 0; i < 3; i++ {
		session := &Session{
			ID:        "exp" + string(rune('a'+i)),
			Secret:    "secret",
			HTML:      "<html>expired</html>",
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		if err := store.CreateSession(session.ID, session.Secret, session.HTML, session.ExpiresAt); err != nil {
			t.Fatalf("Failed to create expired session: %v", err)
		}
	}

	// Create a valid session
	validSession := &Session{
		ID:        "valid",
		Secret:    "secret",
		HTML:      "<html>valid</html>",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateSession(validSession.ID, validSession.Secret, validSession.HTML, validSession.ExpiresAt); err != nil {
		t.Fatalf("Failed to create valid session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Use a faster interval for testing
	StartCleanup(ctx, store, 20*time.Millisecond)

	// Wait for cleanup to run multiple cycles (3 expired sessions should be cleaned)
	maxWait := 500 * time.Millisecond
	start := time.Now()
	for time.Since(start) < maxWait {
		// Check if all expired sessions are gone
		allGone := true
		for i := 0; i < 3; i++ {
			id := "exp" + string(rune('a'+i))
			_, err := store.GetSession(id)
			if err == nil {
				allGone = false
				break
			}
		}
		if allGone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)

	// Verify expired sessions are gone
	for i := 0; i < 3; i++ {
		id := "exp" + string(rune('a'+i))
		_, err := store.GetSession(id)
		if err != ErrSessionNotFound {
			t.Errorf("Session %s should be expired and removed", id)
		}
	}

	// Verify valid session still exists
	_, err = store.GetSession("valid")
	if err != nil {
		t.Error("Valid session should still exist")
	}

	store.Close()
}

// TestCleanup_DoesNotAffectValidSessions tests that cleanup never removes non-expired sessions.
func TestCleanup_DoesNotAffectValidSessions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create a session that expires in a long time
	longExpiry := time.Now().Add(24 * time.Hour)
	session := &Session{
		ID:        "longlived",
		Secret:    "secret",
		HTML:      "<html>long lived</html>",
		CreatedAt: time.Now(),
		ExpiresAt: longExpiry,
	}
	if err := store.CreateSession(session.ID, session.Secret, session.HTML, session.ExpiresAt); err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Run cleanup multiple times with short interval
	StartCleanup(ctx, store, 10*time.Millisecond)

	// Let cleanup run many cycles
	time.Sleep(300 * time.Millisecond)

	cancel()
	time.Sleep(50 * time.Millisecond)

	// Session should still exist
	_, err = store.GetSession("longlived")
	if err != nil {
		t.Errorf("Long-lived session should still exist after multiple cleanups: %v", err)
	}

	store.Close()
}