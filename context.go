// +build go1.7

package sessions

import (
	"context"
	"net/http"
)

func contextGet(r *http.Request, key contextKey) interface{} {
	return r.Context().Value(key)
}

func contextSave(r *http.Request, key contextKey, val interface{}) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, key, val)
	return r.WithContext(ctx)
}

func contextClear(r *http.Request) {
	// no-op for go1.7+
}
