//go:build go1.11
// +build go1.11

package sessions

import (
	"net/http"
	"testing"
)

// Test for setting SameSite field in new http.Cookie from name, value
// and options
func TestNewCookieFromOptionsSameSite(t *testing.T) {
	tests := []struct {
		sameSite http.SameSite
	}{
		{http.SameSiteDefaultMode},
		{http.SameSiteLaxMode},
		{http.SameSiteStrictMode},
	}
	for i, v := range tests {
		options := &Options{
			SameSite: v.sameSite,
		}
		cookie := newCookieFromOptions("", "", options)
		if cookie.SameSite != v.sameSite {
			t.Fatalf("%v: bad cookie sameSite: got %v, want %v", i+1, cookie.SameSite, v.sameSite)
		}
	}
}
