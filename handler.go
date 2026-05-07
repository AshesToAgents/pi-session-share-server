package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

// Handler holds the HTTP handler dependencies.
type Handler struct {
	store        *Store
	baseURL      string // fallback when request headers don't provide enough info
	cookieSecret []byte
}

// NewHandler creates a new Handler instance.
func NewHandler(store *Store, baseURL string, cookieSecret []byte) *Handler {
	return &Handler{
		store:        store,
		baseURL:      baseURL,
		cookieSecret: cookieSecret,
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

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/sessions", h.CreateSession)
		r.Put("/sessions/{id}", h.UpdateSession)
		r.Delete("/sessions/{id}", h.DeleteSession)
	})

	// Public session viewing routes
	r.Route("/s", func(r chi.Router) {
		r.Get("/{id}", h.ViewSession)
		r.Post("/{id}/auth", h.Authenticate)
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
	Password   string `json:"password,omitempty"`
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

	var passwordHash []byte
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		passwordHash = hash
	}

	if err := h.store.CreateSession(id, secret, req.HTML, passwordHash, expiresAt); err != nil {
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

	var passwordHash []byte
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		passwordHash = hash
	}

	session, err := h.store.UpdateSession(id, secret, req.HTML, passwordHash, expiresAt)
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

	// No password set - serve HTML directly
	if len(session.Password) == 0 {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(session.HTML))
		return
	}

	// Password set - check for valid cookie
	cookie, err := r.Cookie(cookieName(id))
	if err != nil || !h.validateCookie(cookie, id) {
		h.servePasswordForm(w, id, "")
		return
	}

	// Valid cookie - serve HTML
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(session.HTML))
}

// Authenticate handles POST /s/{id}/auth
func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		h.serveError(w, "Bad Request", "Session ID required", http.StatusBadRequest)
		return
	}

	session, err := h.store.GetSession(id)
	if err != nil {
		h.serveError(w, "Not Found", "Session not found or has expired", http.StatusNotFound)
		return
	}

	if len(session.Password) == 0 {
		h.serveError(w, "Bad Request", "No password required for this session", http.StatusBadRequest)
		return
	}

	var password string
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/html")
			html := strings.Replace(passwordHTML, "{{error}}", `<p class="error">Invalid request</p>`, 1)
			html = strings.Replace(html, "{{session_id}}", id, 1)
			w.Write([]byte(html))
			return
		}
		password = req.Password
	} else {
		// form-urlencoded (from the password form)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/html")
			html := strings.Replace(passwordHTML, "{{error}}", `<p class="error">Invalid request</p>`, 1)
			html = strings.Replace(html, "{{session_id}}", id, 1)
			w.Write([]byte(html))
			return
		}
		password = r.FormValue("password")
	}

	if err := bcrypt.CompareHashAndPassword(session.Password, []byte(password)); err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html")
		html := strings.Replace(passwordHTML, "{{error}}", `<p class="error">Incorrect password</p>`, 1)
		html = strings.Replace(html, "{{session_id}}", id, 1)
		w.Write([]byte(html))
		return
	}

	// Set HMAC-signed cookie
	h.setAuthCookie(w, id, session.ExpiresAt)

	http.Redirect(w, r, fmt.Sprintf("/s/%s", id), http.StatusSeeOther)
}

// cookieName returns the cookie name for a given session ID.
func cookieName(sessionID string) string {
	return fmt.Sprintf("pi-share-%s", sessionID)
}

// signCookie creates an HMAC-SHA256 signature for the cookie payload.
func (h *Handler) signCookie(payload string) string {
	mac := hmac.New(sha256.New, h.cookieSecret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// validateCookie verifies the cookie signature and expiration.
func (h *Handler) validateCookie(cookie *http.Cookie, sessionID string) bool {
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 2 {
		return false
	}

	payload := fmt.Sprintf("%s:%s", sessionID, parts[1])
	expectedSig := h.signCookie(payload)
	if !hmac.Equal([]byte(parts[0]), []byte(expectedSig)) {
		return false
	}

	// Check expiration
	expiresAt, err := time.Parse(time.RFC3339, parts[1])
	if err != nil {
		return false
	}

	return time.Now().Before(expiresAt)
}

// setAuthCookie sets the HMAC-signed authentication cookie.
func (h *Handler) setAuthCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time) {
	payload := fmt.Sprintf("%s:%s", sessionID, expiresAt.Format(time.RFC3339))
	sig := h.signCookie(payload)
	value := fmt.Sprintf("%s|%s", sig, expiresAt.Format(time.RFC3339))

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(sessionID),
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// servePasswordForm serves the password entry form.
func (h *Handler) servePasswordForm(w http.ResponseWriter, sessionID, errorMsg string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	html := passwordHTML
	if errorMsg != "" {
		html = strings.Replace(html, "{{error}}", fmt.Sprintf(`<p class="error">%s</p>`, errorMsg), 1)
	} else {
		html = strings.Replace(html, "{{error}}", "", 1)
	}
	html = strings.Replace(html, "{{session_id}}", sessionID, 1)

	w.Write([]byte(html))
}

// serveError serves the error page.
func (h *Handler) serveError(w http.ResponseWriter, title, message string, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)

	html := strings.Replace(errorHTML, "{{title}}", title, -1)
	html = strings.Replace(html, "{{message}}", message, 1)

	w.Write([]byte(html))
}
