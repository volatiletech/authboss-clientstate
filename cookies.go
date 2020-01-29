package abclientstate

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
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
func (c CookieStorer) WriteState(w http.ResponseWriter, _ authboss.ClientState, ev []authboss.ClientStateEvent) error {
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
