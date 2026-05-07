package main

import (
	"context"
	"log"
	"time"
)

// StartCleanup starts a background goroutine that periodically cleans up expired sessions.
// It runs until the context is cancelled.
func StartCleanup(ctx context.Context, store *Store, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		log.Printf("Cleanup goroutine started (interval: %s)", interval)

		for {
			select {
			case <-ctx.Done():
				log.Println("Cleanup goroutine stopped")
				return
			case <-ticker.C:
				count, err := store.CleanupExpired()
				if err != nil {
					log.Printf("Cleanup error: %v", err)
					continue
				}
				if count > 0 {
					log.Printf("Cleanup: purged %d expired sessions", count)
				}
			}
		}
	}()
}
