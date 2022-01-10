package sessions

// Matcher defines a function used to identify the correct session and cookie
// for a request which contains multiple session cookies of the same name.
type Matcher func(session *Session) bool

// FirstMatcher returns instructs to use the first session and cookie of a given request
func FirstMatcher(_ *Session) bool {
	return true
}
