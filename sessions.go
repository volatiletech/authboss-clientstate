package abclientstate

import (
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/volatiletech/authboss"
)

// SessionStorer stores sessions in a gorilla session store.
// By default it's backed by cookies, but this can be overridden
// by changing the underlying store manually or using the
// appropriate constructor.
type SessionStorer struct {
	Name string

	sessions.Store
}

// NewSessionStorer creates a new gorilla sessions.CookieStore
// and uses that for underlying storage.
//
// The sessionName is the name that will be used for the session cookie
// on the client (one session has many values).
//
// Also it takes pairs of keys (hmac auth, encryption), and if doing
// key rotation multiple of these pairs. The second key of the pair
// should be set to nil if encryption isn't desired.
//
// Authentication keys should be 32 or 64 bytes.
// Encryption keys should be 16, 24, or 32 bytes for AES-128, AES-192, and AES-256
// respectively.
//
// These docs are prone to doc-rot since they're copied from the gorilla
// session store documentation.
func NewSessionStorer(sessionName string, keypairs ...[]byte) SessionStorer {
	return SessionStorer{
		Name:  sessionName,
		Store: sessions.NewCookieStore(keypairs...),
	}
}

// NewSessionStorerFromExisting takes a store object that's already
// configured and uses it directly. This can be anything that satisfies
// the interface.
//
// sessionName is the name of the cookie/file/whatever on the client or on
// the filesystem etc.
func NewSessionStorerFromExisting(sessionName string, store sessions.Store) SessionStorer {
	return SessionStorer{
		Name:  sessionName,
		Store: store,
	}
}

// ReadState loads the session from the request context
func (s SessionStorer) ReadState(r *http.Request) (authboss.ClientState, error) {
	session, err := s.Store.Get(r, s.Name)
	if err != nil {
		return nil, nil
	}

	cs := &SessionState{
		session: session,
	}

	return cs, nil
}

// WriteState to the responsewriter
func (s SessionStorer) WriteState(w http.ResponseWriter, state authboss.ClientState, ev []authboss.ClientStateEvent) error {
	ses := state.(*SessionState)

	for _, ev := range ev {
		switch ev.Kind {
		case authboss.ClientStateEventPut:
			ses.session.Values[ev.Key] = ev.Value
		case authboss.ClientStateEventDel:
			delete(ses.session.Values, ev.Key)
		}
	}

	return s.Store.Save(nil, w, ses.session)
}
