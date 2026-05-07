package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	// Parse CLI flags with environment variable fallbacks
	port := flag.String("port", getEnv("PORT", "8080"), "Listen port")
	dbPath := flag.String("db", getEnv("DB_PATH", "./sessions.db"), "SQLite database path")
	baseURL := flag.String("base-url", getEnv("BASE_URL", "http://localhost:8080"), "Base URL for generating share links")
	cleanupInterval := flag.String("cleanup-interval", getEnv("CLEANUP_INTERVAL", "5m"), "TTL cleanup sweep interval")
	cookieSecret := flag.String("cookie-secret", getEnv("COOKIE_SECRET", ""), "HMAC key for auth cookies (auto-generated if empty)")

	flag.Parse()

	// Generate random cookie secret if not provided
	secret := *cookieSecret
	if secret == "" {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			log.Fatalf("Failed to generate cookie secret: %v", err)
		}
		secret = hex.EncodeToString(bytes)
		log.Printf("Generated random cookie secret: %s (set COOKIE_SECRET env var to persist)", secret)
	}

	// Parse cleanup interval
	interval, err := time.ParseDuration(*cleanupInterval)
	if err != nil {
		log.Fatalf("Invalid cleanup interval: %v", err)
	}

	// Parse port
	portNum, err := strconv.Atoi(*port)
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}

	// Initialize store
	store, err := NewStore(*dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer store.Close()
	log.Printf("Database opened: %s", *dbPath)

	// Create context for cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup goroutine
	StartCleanup(ctx, store, interval)

	// Initialize handler
	handler := NewHandler(store, *baseURL, []byte(secret))

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", portNum),
		Handler:     handler.Routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %d", portNum)
		log.Printf("Base URL: %s", *baseURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Cancel cleanup goroutine
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

// getEnv returns the environment variable value or a default.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
