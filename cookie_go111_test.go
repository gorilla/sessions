// +build go1.11

package sessions

import (
	"net/http"
	"strconv"
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
		t.Run(strconv.Itoa(i+1), func(t *testing.T) {
			options := &Options{
				SameSite: v.sameSite,
			}
			cookie := newCookieFromOptions("", "", options)
			if cookie.SameSite != v.sameSite {
				t.Fatalf("bad cookie sameSite: got %v, want %v", cookie.SameSite, v.sameSite)
			}
		})
	}
}
