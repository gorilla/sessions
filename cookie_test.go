package sessions

import (
	"testing"
)

// Test for creating new http.Cookie from name, value and options
func TestNewCookieFromOptions(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		path     string
		domain   string
		maxAge   int
		secure   bool
		httpOnly bool
	}{
		{"", "bar", "/foo/bar", "foo.example.com", 3600, true, true},
		{"foo", "", "/foo/bar", "foo.example.com", 3600, true, true},
		{"foo", "bar", "", "foo.example.com", 3600, true, true},
		{"foo", "bar", "/foo/bar", "", 3600, true, true},
		{"foo", "bar", "/foo/bar", "foo.example.com", 0, true, true},
		{"foo", "bar", "/foo/bar", "foo.example.com", 3600, false, true},
		{"foo", "bar", "/foo/bar", "foo.example.com", 3600, true, false},
	}
	for i, v := range tests {
		options := &Options{
			Path:     v.path,
			Domain:   v.domain,
			MaxAge:   v.maxAge,
			Secure:   v.secure,
			HttpOnly: v.httpOnly,
		}
		cookie := newCookieFromOptions(v.name, v.value, options)
		if cookie.Name != v.name {
			t.Fatalf("%v: bad cookie name: got %q, want %q", i+1, cookie.Name, v.name)
		}
		if cookie.Value != v.value {
			t.Fatalf("%v: bad cookie value: got %q, want %q", i+1, cookie.Value, v.value)
		}
		if cookie.Path != v.path {
			t.Fatalf("%v: bad cookie path: got %q, want %q", i+1, cookie.Path, v.path)
		}
		if cookie.Domain != v.domain {
			t.Fatalf("%v: bad cookie domain: got %q, want %q", i+1, cookie.Domain, v.domain)
		}
		if cookie.MaxAge != v.maxAge {
			t.Fatalf("%v: bad cookie maxAge: got %q, want %q", i+1, cookie.MaxAge, v.maxAge)
		}
		if cookie.Secure != v.secure {
			t.Fatalf("%v: bad cookie secure: got %v, want %v", i+1, cookie.Secure, v.secure)
		}
		if cookie.HttpOnly != v.httpOnly {
			t.Fatalf("%v: bad cookie httpOnly: got %v, want %v", i+1, cookie.HttpOnly, v.httpOnly)
		}
	}
}
