// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder() *httptest.ResponseRecorder {
	return &httptest.ResponseRecorder{
		HeaderMap: make(http.Header),
		Body:      new(bytes.Buffer),
	}
}

// ----------------------------------------------------------------------------

type FlashMessage struct {
	Type    int
	Message string
}

func TestFlashes(t *testing.T) {
	var req *http.Request
	var rsp *httptest.ResponseRecorder
	var hdr http.Header
	var err error
	var ok bool
	var cookies []string
	var session *Session
	var flashes []interface{}

	store := NewCookieStore([]byte("secret-key"))

	if store.Options.SameSite != http.SameSiteNoneMode {
		t.Fatalf("cookie store error: default same site is not set to None")
	}

	// Round 1 ----------------------------------------------------------------

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	rsp = NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Get a flash.
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected empty flashes; Got %v", flashes)
	}
	// Add some flashes.
	session.AddFlash("foo")
	session.AddFlash("bar")
	// Custom key.
	session.AddFlash("baz", "custom_key")
	// Save.
	if err = Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	hdr = rsp.Header()
	cookies, ok = hdr["Set-Cookie"]
	if !ok || len(cookies) != 1 {
		t.Fatal("No cookies. Header:", hdr)
	}

	if !strings.Contains(cookies[0], "SameSite=None") || !strings.Contains(cookies[0], "Secure") {
		t.Fatal("Set-Cookie does not contains SameSite=None with Secure, cookie string:", cookies[0])
	}

	if _, err = store.Get(req, "session:key"); err.Error() != "sessions: invalid character in cookie name: session:key" {
		t.Fatalf("Expected error due to invalid cookie name")
	}

	// Round 2 ----------------------------------------------------------------

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Check all saved values.
	flashes = session.Flashes()
	if len(flashes) != 2 {
		t.Fatalf("Expected flashes; Got %v", flashes)
	}
	if flashes[0] != "foo" || flashes[1] != "bar" {
		t.Errorf("Expected foo,bar; Got %v", flashes)
	}
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected dumped flashes; Got %v", flashes)
	}
	// Custom key.
	flashes = session.Flashes("custom_key")
	if len(flashes) != 1 {
		t.Errorf("Expected flashes; Got %v", flashes)
	} else if flashes[0] != "baz" {
		t.Errorf("Expected baz; Got %v", flashes)
	}
	flashes = session.Flashes("custom_key")
	if len(flashes) != 0 {
		t.Errorf("Expected dumped flashes; Got %v", flashes)
	}

	// Round 3 ----------------------------------------------------------------
	// Custom type

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	rsp = NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Get a flash.
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected empty flashes; Got %v", flashes)
	}
	// Add some flashes.
	session.AddFlash(&FlashMessage{42, "foo"})
	// Save.
	if err = Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	hdr = rsp.Header()
	cookies, ok = hdr["Set-Cookie"]
	if !ok || len(cookies) != 1 {
		t.Fatal("No cookies. Header:", hdr)
	}

	// Round 4 ----------------------------------------------------------------
	// Custom type

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Check all saved values.
	flashes = session.Flashes()
	if len(flashes) != 1 {
		t.Fatalf("Expected flashes; Got %v", flashes)
	}
	custom := flashes[0].(FlashMessage)
	if custom.Type != 42 || custom.Message != "foo" {
		t.Errorf("Expected %#v, got %#v", FlashMessage{42, "foo"}, custom)
	}

	// Round 5 ----------------------------------------------------------------
	// Check if a request shallow copy resets the request context data store.

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)

	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Put a test value into the session data store.
	session.Values["test"] = "test-value"

	// Create a shallow copy of the request.
	req = req.WithContext(req.Context())

	// Get the session again.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Check if the previous inserted value still exists.
	if session.Values["test"] == nil {
		t.Fatalf("Session test value is lost in the request context!")
	}

	// Check if the previous inserted value has the same value.
	if session.Values["test"] != "test-value" {
		t.Fatalf("Session test value is changed in the request context!")
	}
}

func TestCookieStoreMapPanic(t *testing.T) {
	defer func() {
		err := recover()
		if err != nil {
			t.Fatal(err)
		}
	}()

	store := NewCookieStore([]byte("aaa0defe5d2839cbc46fc4f080cd7adc"))
	req, err := http.NewRequest("GET", "http://www.example.com", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}
	w := httptest.NewRecorder()

	session := NewSession(store, "hello")

	session.Values["data"] = "hello-world"

	err = session.Save(req, w)
	if err != nil {
		t.Fatal("failed to save session", err)
	}
}

func TestRegistryConcurrentGetSameSession(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	registry := GetRegistry(req)
	store := NewCookieStore([]byte("test-secret-key-1234567890123456"))

	const goroutines = 50
	var wg sync.WaitGroup
	sessions := make([]*Session, goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessions[idx], errors[idx] = registry.Get(store, "shared-session")
		}(i)
	}
	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("goroutine %d returned error: %v", i, err)
		}
	}
	for i := 1; i < goroutines; i++ {
		if sessions[i] != sessions[0] {
			t.Fatalf("goroutine %d received different session instance than goroutine 0", i)
		}
	}
}

func TestRegistryConcurrentGetDifferentSessions(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	registry := GetRegistry(req)
	store := NewCookieStore([]byte("test-secret-key-1234567890123456"))

	const goroutines = 100
	var wg sync.WaitGroup
	sessions := make([]*Session, goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("session-%d", idx%10)
			sessions[idx], errors[idx] = registry.Get(store, name)
		}(i)
	}
	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("goroutine %d returned error: %v", i, err)
		}
		if sessions[i] == nil {
			t.Fatalf("goroutine %d received nil session", i)
		}
	}

	for i := 0; i < goroutines; i++ {
		for j := i + 1; j < goroutines; j++ {
			if i%10 == j%10 && sessions[i] != sessions[j] {
				t.Fatalf("sessions with identical name should share pointer instance")
			}
		}
	}
}

func TestRegistryConcurrentGetAndSave(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	registry := GetRegistry(req)
	store := NewCookieStore([]byte("test-secret-key-1234567890123456"))

	const numGetters = 40
	const numSavers = 20
	var wg sync.WaitGroup

	for i := 0; i < numGetters; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-session-%d", idx%5)
			sess, err := registry.Get(store, name)
			if err != nil {
				t.Errorf("Get failed: %v", err)
			}
			if sess == nil {
				t.Errorf("Get returned nil session")
			}
		}(i)
	}

	for i := 0; i < numSavers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			if err := registry.Save(w); err != nil {
				t.Errorf("Save failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestRegistryConcurrentSave(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	registry := GetRegistry(req)
	store := NewCookieStore([]byte("test-secret-key-1234567890123456"))

	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("session-%d", i)
		s, err := registry.Get(store, name)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		s.Values["key"] = i
	}

	const goroutines = 30
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			if err := registry.Save(w); err != nil {
				t.Errorf("Save failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestStoreConcurrentGet(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	store := NewCookieStore([]byte("test-secret-key-1234567890123456"))

	// Pre-populate registry context so goroutines query the shared registry
	_ = GetRegistry(req)

	const goroutines = 50
	var wg sync.WaitGroup
	sessions := make([]*Session, goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessions[idx], errors[idx] = store.Get(req, "user-session")
		}(i)
	}
	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
		if sessions[i] == nil {
			t.Fatalf("goroutine %d session is nil", i)
		}
	}
	for i := 1; i < goroutines; i++ {
		if sessions[i] != sessions[0] {
			t.Fatalf("goroutine %d received different session instance than goroutine 0", i)
		}
	}
}

func TestRegistrySaveMissingStore(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	registry := &Registry{
		request:  req,
		sessions: make(map[string]sessionInfo),
	}
	registry.sessions["orphan"] = sessionInfo{
		s: &Session{name: "orphan", store: nil},
		e: nil,
	}

	w := httptest.NewRecorder()
	err = registry.Save(w)
	if err == nil {
		t.Fatal("expected error for missing store, got nil")
	}
	if !strings.Contains(err.Error(), "missing store for session \"orphan\"") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRegistryUninitializedMap(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	registry := &Registry{request: req}
	store := NewCookieStore([]byte("test-secret-key-1234567890123456"))

	sess, err := registry.Get(store, "lazy-init")
	if err != nil {
		t.Fatalf("Get failed on uninitialized map: %v", err)
	}
	if sess == nil {
		t.Fatal("expected session instance, got nil")
	}

	w := httptest.NewRecorder()
	emptyReg := &Registry{request: req}
	if err := emptyReg.Save(w); err != nil {
		t.Fatalf("Save failed on uninitialized map: %v", err)
	}
}

func init() {
	gob.Register(FlashMessage{})
}
