package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// storeReturningError is a Store whose New always fails, returning a nil
// session together with an error.
type storeReturningError struct{}

func (storeReturningError) Get(r *http.Request, name string) (*Session, error) {
	return nil, http.ErrNoCookie
}

func (storeReturningError) New(r *http.Request, name string) (*Session, error) {
	return nil, http.ErrNoCookie
}

func (storeReturningError) Save(r *http.Request, w http.ResponseWriter, s *Session) error {
	return nil
}

// TestRegistryGet_StoreNewError verifies that Registry.Get does not panic with
// a nil-pointer dereference when a store's New returns (nil, err); it should
// surface the error instead.
func TestRegistryGet_StoreNewError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	reg := GetRegistry(req)

	session, err := reg.Get(storeReturningError{}, "session-name")
	if err == nil {
		t.Fatal("expected an error from Get when store.New fails")
	}
	if session != nil {
		t.Fatalf("expected a nil session when store.New fails, got %#v", session)
	}
}
