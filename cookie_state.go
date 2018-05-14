package abclientstate

// CookieState is an authboss.ClientState implementation to hold
// cookie state for the duration of the request
type CookieState map[string]string

// Get a cookie's value
func (c CookieState) Get(key string) (string, bool) {
	cookie, ok := c[key]
	return cookie, ok
}
