package sessions

import (
	"strconv"
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
		t.Run(strconv.Itoa(i+1), func(t *testing.T) {
			options := &Options{
				Path:     v.path,
				Domain:   v.domain,
				MaxAge:   v.maxAge,
				Secure:   v.secure,
				HttpOnly: v.httpOnly,
			}
			cookie := newCookieFromOptions(v.name, v.value, options)
			if cookie.Name != v.name {
				t.Fatalf("bad cookie name: got %q, want %q", cookie.Name, v.name)
			}
			if cookie.Value != v.value {
				t.Fatalf("bad cookie value: got %q, want %q", cookie.Value, v.value)
			}
			if cookie.Path != v.path {
				t.Fatalf("bad cookie path: got %q, want %q", cookie.Path, v.path)
			}
			if cookie.Domain != v.domain {
				t.Fatalf("bad cookie domain: got %q, want %q", cookie.Domain, v.domain)
			}
			if cookie.MaxAge != v.maxAge {
				t.Fatalf("bad cookie maxAge: got %q, want %q", cookie.MaxAge, v.maxAge)
			}
			if cookie.Secure != v.secure {
				t.Fatalf("bad cookie secure: got %v, want %v", cookie.Secure, v.secure)
			}
			if cookie.HttpOnly != v.httpOnly {
				t.Fatalf("bad cookie httpOnly: got %v, want %v", cookie.HttpOnly, v.httpOnly)
			}
		})
	}
}
