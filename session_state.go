package abclientstate

import "github.com/gorilla/sessions"

// SessionState is an authboss.ClientState implementation that
// holds the request's session values for the duration of the request.
type SessionState struct {
	session *sessions.Session
}

// Get a key from the session
func (s SessionState) Get(key string) (string, bool) {
	str, ok := s.session.Values[key]
	if !ok {
		return "", false
	}
	value := str.(string)

	return value, ok
}
