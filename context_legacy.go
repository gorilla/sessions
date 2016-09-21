// +build !go1.7

package sessions

import (
	"net/http"

	"github.com/gorilla/context"
)

func contextGet(r *http.Request, key contextKey) interface{} {
	return context.Get(r, key)
}

func contextSave(r *http.Request, key contextKey, val interface{}) *http.Request {
	context.Set(r, key, val)
	return r
}

func contextClear(r *http.Request) {
	context.Clear(r)
}
