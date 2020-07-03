package abclientstate

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss/v3"
)

var (
	defaultCookieList = []string{authboss.CookieRemember}
)

// CookieStorer writes and reads cookies to an underlying
// gorilla secure cookie storage.
//
// Because it embeds the SecureCookie piece this can be used
// as the cookie storage for your entire application (rather than
// only as a stub for authboss).
type CookieStorer struct {
	Cookies []string
	*securecookie.SecureCookie

	// Defaults empty
	Domain string
	// Defaults to /
	Path string
	// Defaults to 1 month
	MaxAge int
	// Defaults to true
	HTTPOnly bool
	// Defaults to true
	Secure bool
	// Samesite defaults to 0 or "off"
	SameSite http.SameSite
}

// NewCookieStorer constructor simply wraps the constructor for
// securecookie.New. The parameters are the hash key and the block key.
//
// The hash key is required to authenticate the cookie with HMAC (32 or 64 bytes)
//
// The block key is optional to encrypt the cookie value (set to nil to disable encryption)
// For AES (the default encryption algorithm) 16, 24, or 32 byte keys select AES-128,
// AES-192, AES-256
// respectively.
//
// Ensure you verify the security options for the cookie on the CookieStorer.
//
// This documentation was copied from securecookie.New and is prone to doc-rot. Please
// consult the documentation there too.
func NewCookieStorer(hashKey, blockKey []byte) CookieStorer {
	return NewCookieStorerFromExisting(securecookie.New(hashKey, blockKey))
}

// NewCookieStorerFromExisting takes a preconfigured
// secure cookie instance and simply uses it.
//
// Ensure you verify the additional security options for the cookie on the
// CookieStorer. This method creates a cookie storer with the options tuned
// for high security by default.
func NewCookieStorerFromExisting(storage *securecookie.SecureCookie) CookieStorer {
	return CookieStorer{
		Cookies:      defaultCookieList,
		SecureCookie: storage,

		Path: "/",
		// 1 month in seconds
		MaxAge:   int((time.Hour * 730) / time.Second),
		HTTPOnly: true,
		Secure:   true,
	}
}

// ReadState from the request
func (c CookieStorer) ReadState(r *http.Request) (authboss.ClientState, error) {
	cs := make(CookieState)

	for _, cookie := range r.Cookies() {
		for _, n := range c.Cookies {
			if n == cookie.Name {
				var str string
				if err := c.SecureCookie.Decode(n, cookie.Value, &str); err != nil {
					if e, ok := err.(securecookie.Error); ok {
						// Ignore bad cookies, this means that the client
						// may have bad cookies for a long time, but they should
						// eventually be overwritten by the application.
						if e.IsDecode() {
							continue
						}
					}
					return nil, err
				}

				cs[n] = str
			}
		}
	}

	return cs, nil
}

// WriteState to the responsewriter
func (c CookieStorer) WriteState(w http.ResponseWriter, state authboss.ClientState, ev []authboss.ClientStateEvent) error {
	for _, ev := range ev {
		switch ev.Kind {
		case authboss.ClientStateEventPut:
			encoded, err := c.SecureCookie.Encode(ev.Key, ev.Value)
			if err != nil {
				return errors.Wrap(err, "failed to encode cookie")
			}

			cookie := &http.Cookie{
				Expires: time.Now().UTC().AddDate(1, 0, 0),
				Name:    ev.Key,
				Value:   encoded,

				Domain:   c.Domain,
				Path:     c.Path,
				MaxAge:   c.MaxAge,
				HttpOnly: c.HTTPOnly,
				Secure:   c.Secure,
				SameSite: c.SameSite,
			}
			http.SetCookie(w, cookie)
		case authboss.ClientStateEventDel:
			cookie := &http.Cookie{
				MaxAge: -1,
				Name:   ev.Key,
				Domain: c.Domain,
				Path:   c.Path,
			}
			http.SetCookie(w, cookie)
		}
	}

	return nil
}
