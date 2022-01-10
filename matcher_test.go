package sessions

import "testing"

func TestFirstMatcher(t *testing.T) {
	if !FirstMatcher(nil) {
		t.Error("First matcher should match first session")
	}
}
