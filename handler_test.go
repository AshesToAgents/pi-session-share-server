package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// newTestHandler creates a handler with an in-memory store for testing.
func newTestHandler(t *testing.T) (*Handler, *Store) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create in-memory store: %v", err)
	}
	handler := NewHandler(store, "http://localhost:8080")
	return handler, store
}

// --- POST /api/sessions tests ---

func TestCreateSession_Success(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	body := CreateSessionRequest{
		HTML:       "<html>Test Session</html>",
		TTLSeconds: 3600,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp CreateSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.ID == "" {
		t.Error("Response should contain an ID")
	}
	if resp.Secret == "" {
		t.Error("Response should contain a secret")
	}
	if resp.ExpiresAt == "" {
		t.Error("Response should contain expires_at")
	}
	if resp.URL == "" {
		t.Error("Response should contain a URL")
	}

	// Verify session was actually created
	session, err := store.GetSession(resp.ID)
	if err != nil {
		t.Errorf("Session should exist in store: %v", err)
	}
	if session.HTML != body.HTML {
		t.Errorf("HTML mismatch in store")
	}
}

func TestCreateSession_DefaultTTL(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	body := CreateSessionRequest{
		HTML: "<html>No TTL</html>",
		// TTLSeconds omitted - should default to 86400
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var resp CreateSessionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Check expires_at is approximately 24 hours from now
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("Invalid expires_at format: %v", err)
	}

	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := expiresAt.Sub(expectedExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("Expected ~24h expiry, got diff of %v", diff)
	}
}

func TestCreateSession_EmptyHTML(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	body := CreateSessionRequest{
		HTML: "", // Empty HTML
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// --- PUT /api/sessions/{id} tests ---

func TestUpdateSession_Success(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	// First create a session
	createResp := createTestSessionViaRouter(t, router, "<html>original</html>", 3600)

	// Now update it
	updateBody := CreateSessionRequest{
		HTML:       "<html>updated</html>",
		TTLSeconds: 7200,
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req := httptest.NewRequest(http.MethodPut, "/api/sessions/"+createResp.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createResp.Secret)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	// Verify update in store
	session, err := store.GetSession(createResp.ID)
	if err != nil {
		t.Errorf("Failed to get updated session: %v", err)
	}
	if session.HTML != "<html>updated</html>" {
		t.Errorf("HTML not updated in store, got: %s", session.HTML)
	}
}

func TestUpdateSession_NoAuthHeader(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "<html>test</html>", 3600)

	updateBody := CreateSessionRequest{
		HTML: "<html>updated</html>",
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req := httptest.NewRequest(http.MethodPut, "/api/sessions/"+createResp.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSession_WrongSecret(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "<html>test</html>", 3600)

	updateBody := CreateSessionRequest{
		HTML: "<html>updated</html>",
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req := httptest.NewRequest(http.MethodPut, "/api/sessions/"+createResp.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrongsecret")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSession_NonExistent(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	updateBody := CreateSessionRequest{
		HTML: "<html>updated</html>",
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req := httptest.NewRequest(http.MethodPut, "/api/sessions/nonexistent", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer anysecret")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// --- DELETE /api/sessions/{id} tests ---

func TestDeleteSession_Success(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "<html>to delete</html>", 3600)

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/"+createResp.ID, nil)
	req.Header.Set("Authorization", "Bearer "+createResp.Secret)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Verify deleted
	_, err := store.GetSession(createResp.ID)
	if err != ErrSessionNotFound {
		t.Error("Session should be deleted")
	}
}

func TestDeleteSession_WrongSecret(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "<html>test</html>", 3600)

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/"+createResp.ID, nil)
	req.Header.Set("Authorization", "Bearer wrongsecret")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestDeleteSession_NonExistent(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer anysecret")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// --- GET /s/{id} tests ---

func TestViewSession_ServesViewerPage(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	testHTML := "<html>public content</html>"
	createResp := createTestSessionViaRouter(t, router, testHTML, 3600)

	req := httptest.NewRequest(http.MethodGet, "/s/"+createResp.ID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Expected Content-Type text/html, got %s", w.Header().Get("Content-Type"))
	}
	// Response should contain the viewer page with embedded HTML
	body := w.Body.String()
	if !bytes.Contains([]byte(body), []byte(testHTML)) {
		t.Errorf("Expected response to contain embedded HTML: %s", testHTML)
	}
	// Response should contain JavaScript for decryption
	if !bytes.Contains([]byte(body), []byte("AES-GCM")) && !bytes.Contains([]byte(body), []byte("crypto.subtle")) {
		t.Errorf("Expected response to contain JavaScript (AES-GCM or crypto.subtle)")
	}
}

func TestViewSession_NonExistent(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	req := httptest.NewRequest(http.MethodGet, "/s/nonexistent", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// --- Helper functions ---

func createTestSessionViaRouter(t *testing.T, router *chi.Mux, html string, ttlSeconds int) *CreateSessionResponse {
	body := CreateSessionRequest{
		HTML:       html,
		TTLSeconds: ttlSeconds,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create test session: %d - %s", w.Code, w.Body.String())
	}

	var resp CreateSessionResponse
	json.NewDecoder(w.Body).Decode(&resp)
	return &resp
}

// --- Integration tests using the full router ---

func TestFullRouter_CreateAndView(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	testHTML := "<html>Full Router Test</html>"
	// Create session via API
	createResp := createTestSessionViaRouter(t, router, testHTML, 3600)

	// View session - should return viewer page with embedded HTML
	req2 := httptest.NewRequest(http.MethodGet, "/s/"+createResp.ID, nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("View failed: %d - %s", w2.Code, w2.Body.String())
	}
	// Verify the viewer page contains the embedded HTML
	if !bytes.Contains([]byte(w2.Body.String()), []byte(testHTML)) {
		t.Errorf("Expected viewer page to contain embedded HTML, got: %s", w2.Body.String())
	}
}
