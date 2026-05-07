package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	handler := NewHandler(store, "http://localhost:8080", []byte("test-cookie-secret-12345678901234567890"))
	return handler, store
}

// Helper to set auth cookie on a request
func setAuthCookie(req *http.Request, sessionID string, expiresAt time.Time, secret []byte) {
	handler := &Handler{cookieSecret: secret}
	payload := fmt.Sprintf("%s:%s", sessionID, expiresAt.Format(time.RFC3339))
	sig := handler.signCookie(payload)
	value := fmt.Sprintf("%s|%s", sig, expiresAt.Format(time.RFC3339))
	req.AddCookie(&http.Cookie{
		Name:  cookieName(sessionID),
		Value: value,
	})
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
	createResp := createTestSessionViaRouter(t, router, "<html>original</html>", 3600, nil)

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

	createResp := createTestSessionViaRouter(t, router, "<html>test</html>", 3600, nil)

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

	createResp := createTestSessionViaRouter(t, router, "<html>test</html>", 3600, nil)

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

	createResp := createTestSessionViaRouter(t, router, "<html>to delete</html>", 3600, nil)

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

	createResp := createTestSessionViaRouter(t, router, "<html>test</html>", 3600, nil)

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

func TestViewSession_Unprotected(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "<html>public content</html>", 3600, nil)

	req := httptest.NewRequest(http.MethodGet, "/s/"+createResp.ID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Expected Content-Type text/html, got %s", w.Header().Get("Content-Type"))
	}
	if w.Body.String() != "<html>public content</html>" {
		t.Errorf("Expected HTML body, got %s", w.Body.String())
	}
}

func TestViewSession_ProtectedNoCookie(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	// Create with password
	createResp := createTestSessionViaRouter(t, router, "secret html", 3600, stringPtr("mypassword"))

	req := httptest.NewRequest(http.MethodGet, "/s/"+createResp.ID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 (password form), got %d. Body: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Expected Content-Type text/html, got %s", w.Header().Get("Content-Type"))
	}
	// Body should contain password form elements
	if !bytes.Contains(w.Body.Bytes(), []byte("password")) {
		t.Errorf("Expected password form in response, got %s", w.Body.String())
	}
}

func TestViewSession_ProtectedWithValidCookie(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	// Create with password
	createResp := createTestSessionViaRouter(t, router, "secret html", 3600, stringPtr("mypassword"))

	// Get the session to get expiration time
	session, err := store.GetSession(createResp.ID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/s/"+createResp.ID, nil)
	setAuthCookie(req, createResp.ID, session.ExpiresAt, handler.cookieSecret)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "secret html" {
		t.Errorf("Expected secret HTML, got %s", w.Body.String())
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

// --- POST /s/{id}/auth tests ---

func TestAuthenticate_Success(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "secret html", 3600, stringPtr("mypassword"))

	authReq := struct {
		Password string `json:"password"`
	}{Password: "mypassword"}
	bodyBytes, _ := json.Marshal(authReq)

	req := httptest.NewRequest(http.MethodPost, "/s/"+createResp.ID+"/auth", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Check redirect location
	location := w.Header().Get("Location")
	if location != "/s/"+createResp.ID {
		t.Errorf("Expected redirect to /s/%s, got %s", createResp.ID, location)
	}

	// Check cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == cookieName(createResp.ID) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected auth cookie to be set")
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "secret html", 3600, stringPtr("mypassword"))

	authReq := struct {
		Password string `json:"password"`
	}{Password: "wrongpassword"}
	bodyBytes, _ := json.Marshal(authReq)

	req := httptest.NewRequest(http.MethodPost, "/s/"+createResp.ID+"/auth", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Should return retry form
	if !bytes.Contains(w.Body.Bytes(), []byte("error")) && !bytes.Contains(w.Body.Bytes(), []byte("Incorrect")) {
		t.Errorf("Expected error message in response, got %s", w.Body.String())
	}
}

func TestAuthenticate_NoPassword(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	// Session without password
	createResp := createTestSessionViaRouter(t, router, "no password session", 3600, nil)

	authReq := struct {
		Password string `json:"password"`
	}{Password: "anypassword"}
	bodyBytes, _ := json.Marshal(authReq)

	req := httptest.NewRequest(http.MethodPost, "/s/"+createResp.ID+"/auth", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthenticate_FormEncoded(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "secret html", 3600, stringPtr("mypassword"))

	form := url.Values{"password": {"mypassword"}}
	req := httptest.NewRequest(http.MethodPost, "/s/"+createResp.ID+"/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d. Body: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if location != "/s/"+createResp.ID {
		t.Errorf("Expected redirect to /s/%s, got %s", createResp.ID, location)
	}
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == cookieName(createResp.ID) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected auth cookie to be set")
	}
}

func TestAuthenticate_FormEncodedWrongPassword(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	createResp := createTestSessionViaRouter(t, router, "secret html", 3600, stringPtr("mypassword"))

	form := url.Values{"password": {"wrongpassword"}}
	req := httptest.NewRequest(http.MethodPost, "/s/"+createResp.ID+"/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// --- Helper functions ---

func stringPtr(s string) *string {
	return &s
}

func createTestSessionViaRouter(t *testing.T, router *chi.Mux, html string, ttlSeconds int, password *string) *CreateSessionResponse {
	body := CreateSessionRequest{
		HTML:       html,
		TTLSeconds: ttlSeconds,
	}
	if password != nil {
		body.Password = *password
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

	// Create session
	body := CreateSessionRequest{
		HTML:       "<html>Full Router Test</html>",
		TTLSeconds: 3600,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Create failed: %d - %s", w.Code, w.Body.String())
	}

	var resp CreateSessionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// View session
	req2 := httptest.NewRequest(http.MethodGet, "/s/"+resp.ID, nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("View failed: %d - %s", w2.Code, w2.Body.String())
	}
	if w2.Body.String() != "<html>Full Router Test</html>" {
		t.Errorf("HTML mismatch: %s", w2.Body.String())
	}
}

func TestFullRouter_CreateProtectedAndAuthenticate(t *testing.T) {
	t.Parallel()

	handler, store := newTestHandler(t)
	defer store.Close()
	router := handler.Routes()

	// Create protected session
	body := CreateSessionRequest{
		HTML:       "<html>Protected Content</html>",
		Password:   "correctpassword",
		TTLSeconds: 3600,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp CreateSessionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Try to view without auth - should get password form
	req2 := httptest.NewRequest(http.MethodGet, "/s/"+resp.ID, nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected password form, got %d", w2.Code)
	}

	// Authenticate with wrong password
	authReq := struct {
		Password string `json:"password"`
	}{Password: "wrongpassword"}
	authBody, _ := json.Marshal(authReq)

	req3 := httptest.NewRequest(http.MethodPost, "/s/"+resp.ID+"/auth", bytes.NewReader(authBody))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	if w3.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for wrong password, got %d", w3.Code)
	}

	// Authenticate with correct password
	authReq2 := struct {
		Password string `json:"password"`
	}{Password: "correctpassword"}
	authBody2, _ := json.Marshal(authReq2)

	req4 := httptest.NewRequest(http.MethodPost, "/s/"+resp.ID+"/auth", bytes.NewReader(authBody2))
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	router.ServeHTTP(w4, req4)

	if w4.Code != http.StatusSeeOther {
		t.Errorf("Expected 303 redirect, got %d", w4.Code)
	}

	// Now view with the cookie that was set
	cookies := w4.Result().Cookies()
	req5 := httptest.NewRequest(http.MethodGet, "/s/"+resp.ID, nil)
	for _, c := range cookies {
		req5.AddCookie(c)
	}
	w5 := httptest.NewRecorder()
	router.ServeHTTP(w5, req5)

	if w5.Code != http.StatusOK {
		t.Errorf("Expected 200 with cookie, got %d - %s", w5.Code, w5.Body.String())
	}

	_ = store // unused but keeping for consistency
}