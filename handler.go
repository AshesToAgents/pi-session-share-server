package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Handler holds the HTTP handler dependencies.
type Handler struct {
	store   *Store
	baseURL string // fallback when request headers don't provide enough info
}

// NewHandler creates a new Handler instance.
func NewHandler(store *Store, baseURL string) *Handler {
	return &Handler{
		store:   store,
		baseURL: baseURL,
	}
}

// resolveBaseURL derives the base URL from the request, falling back to the configured value.
func (h *Handler) resolveBaseURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		return h.baseURL
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// Routes returns the chi router with all routes configured.
func (h *Handler) Routes() *chi.Mux {
	r := chi.NewRouter()

	// Root — serve README
	r.Get("/", h.ServeReadme)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/sessions", h.CreateSession)
		r.Put("/sessions/{id}", h.UpdateSession)
		r.Delete("/sessions/{id}", h.DeleteSession)
	})

	// Public session viewing routes
	r.Route("/s", func(r chi.Router) {
		r.Get("/{id}", h.ViewSession)
	})

	return r
}

// generateID creates an 8-character URL-safe random string.
func generateID() (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:8], nil
}

// generateSecret creates a 32-character crypto-random string.
func generateSecret() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSessionRequest represents the JSON request for creating a session.
type CreateSessionRequest struct {
	HTML       string `json:"html"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// CreateSessionResponse represents the JSON response after creating a session.
type CreateSessionResponse struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	ExpiresAt string `json:"expires_at"`
	URL       string `json:"url"`
}

// CreateSession handles POST /api/sessions
func (h *Handler) CreateSession(w http.ResponseWriter, r *http.Request) {
	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.HTML == "" {
		http.Error(w, "html is required", http.StatusBadRequest)
		return
	}

	// Default TTL to 86400 seconds (24 hours)
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 86400
	}

	id, err := generateID()
	if err != nil {
		http.Error(w, "Failed to generate ID", http.StatusInternalServerError)
		return
	}

	secret, err := generateSecret()
	if err != nil {
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)

	if err := h.store.CreateSession(id, secret, req.HTML, expiresAt); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	resp := CreateSessionResponse{
		ID:        id,
		Secret:    secret,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		URL:       fmt.Sprintf("%s/s/%s", strings.TrimSuffix(h.resolveBaseURL(r), "/"), id),
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// UpdateSession handles PUT /api/sessions/{id}
func (h *Handler) UpdateSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	secret := extractBearerToken(r)
	if secret == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.HTML == "" {
		http.Error(w, "html is required", http.StatusBadRequest)
		return
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 86400
	}

	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)

	session, err := h.store.UpdateSession(id, secret, req.HTML, expiresAt)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrForbidden) {
			http.Error(w, "Forbidden: secret mismatch", http.StatusForbidden)
			return
		}
		http.Error(w, "Failed to update session", http.StatusInternalServerError)
		return
	}

	resp := CreateSessionResponse{
		ID:        session.ID,
		Secret:    session.Secret,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		URL:       fmt.Sprintf("%s/s/%s", strings.TrimSuffix(h.resolveBaseURL(r), "/"), session.ID),
	}

	json.NewEncoder(w).Encode(resp)
}

// DeleteSession handles DELETE /api/sessions/{id}
func (h *Handler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	secret := extractBearerToken(r)
	if secret == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	err := h.store.DeleteSession(id, secret)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrForbidden) {
			http.Error(w, "Forbidden: secret mismatch", http.StatusForbidden)
			return
		}
		http.Error(w, "Failed to delete session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractBearerToken extracts the Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// ViewSession handles GET /s/{id}
func (h *Handler) ViewSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		h.serveError(w, "Not Found", "Session not found", http.StatusNotFound)
		return
	}

	session, err := h.store.GetSession(id)
	if err != nil {
		h.serveError(w, "Not Found", "Session not found or has expired", http.StatusNotFound)
		return
	}

	// Always serve the viewer page with embedded ciphertext
	w.Header().Set("Content-Type", "text/html")
	html := strings.Replace(viewerHTML, "{{ciphertext}}", session.HTML, 1)
	w.Write([]byte(html))
}

// ServeReadme serves the README at the root route.
func (h *Handler) ServeReadme(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(readmeHTML)
}

func (h *Handler) serveError(w http.ResponseWriter, title, message string, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)

	html := strings.Replace(errorHTML, "{{title}}", title, -1)
	html = strings.Replace(html, "{{message}}", message, 1)

	w.Write([]byte(html))
}
