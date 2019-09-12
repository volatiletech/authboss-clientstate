package abclientstate

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
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
// This creates the session storer with the most secure options: MaxAge=0,
// Secure=true, HttpOnly=true. You can change them after it's created by
// converting the Store or simply create your own sessions.NewCookieStore
// and set its options manually.
//
// These docs are prone to doc-rot since they're copied from the gorilla
// session store documentation.
func NewSessionStorer(sessionName string, keypairs ...[]byte) SessionStorer {
	cookieStore := sessions.NewCookieStore(keypairs...)

	// 12 hours, set this to something because if we don't then sessions
	// may never expire as long as the browser remains opened.
	cookieStore.MaxAge(int((time.Hour * 12) / time.Second))
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.Secure = true

	return SessionStorer{
		Name:  sessionName,
		Store: cookieStore,
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
	// Note that implementers of Get in gorilla all return a new session
	session, err := s.Store.Get(r, s.Name)
	if err != nil {
		e, ok := err.(securecookie.Error)
		if ok && !e.IsDecode() {
			// We ignore decoding errors, but nothing else
			return nil, err
		}

		// Get in gorilla does not return new sessions if a bad one exists
		// New() also happens to parse the cookie in r, and returns the same
		// decode error but still returns a new session
		session, err = s.Store.New(r, s.Name)
		if session == nil {
			return nil, errors.New("could not create new session")
		}
	}

	cs := &SessionState{
		session: session,
	}

	return cs, nil
}

// WriteState to the responsewriter
func (s SessionStorer) WriteState(w http.ResponseWriter, state authboss.ClientState, ev []authboss.ClientStateEvent) error {
	// This should never be nil (despite what authboss.ClientStateReadWriter
	// interface says) because all Get methods return a new session in gorilla.
	// In cases where Get returns an error, we ensure we create a new session
	ses := state.(*SessionState)

	for _, ev := range ev {
		switch ev.Kind {
		case authboss.ClientStateEventPut:
			ses.session.Values[ev.Key] = ev.Value
		case authboss.ClientStateEventDel:
			delete(ses.session.Values, ev.Key)

		case authboss.ClientStateEventDelAll:
			if len(ev.Key) == 0 {
				// Delete the entire session
				ses.session.Options.MaxAge = -1
			} else {
				whitelist := strings.Split(ev.Key, ",")
				for key := range ses.session.Values {
					if k, ok := key.(string); ok {

						dontDelete := false
						for _, w := range whitelist {
							if w == k {
								dontDelete = true
								break
							}
						}

						if !dontDelete {
							delete(ses.session.Values, key)
						}
					}
				}
			}
		}
	}

	return s.Store.Save(nil, w, ses.session)
}
