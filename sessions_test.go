package abclientstate

import (
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/volatiletech/authboss"
)

func TestExpiry(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	storer := NewSessionStorer("x", key, nil)
	cookieStore := storer.Store.(*sessions.CookieStore)
	cookieStore.MaxAge(1)
	cookieStore.Options.HttpOnly = false
	cookieStore.Options.Secure = false

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	oldState, err := storer.ReadState(r)
	if err != nil {
		t.Fatal(err)
	}

	evs := []authboss.ClientStateEvent{{Kind: authboss.ClientStateEventPut, Key: "hello", Value: "World"}}
	if err := storer.WriteState(w, oldState, evs); err != nil {
		t.Fatal(err)
	}

	w.Flush()
	cookie := w.Header().Get("Set-Cookie")
	if len(cookie) == 0 {
		t.Error("it should have set a cookie")
	}

	time.Sleep(time.Second * 2)

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookie)
	oldState, err = storer.ReadState(r)
	if err != nil {
		t.Fatal(err)
	}

	if val, ok := oldState.Get("hello"); ok || len(val) != 0 {
		t.Error("it should not have had a value:", val)
	}
}
