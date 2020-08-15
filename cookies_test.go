package abclientstate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/volatiletech/authboss/v3"
)

func TestGetCookieState(t *testing.T) {
	t.Parallel()
	var c CookieState = map[string]string{"hello": "world"}
	val, ok := c.Get("hello")
	if !ok {
		t.Error("could not get cookie state")
	}
	if val != "world" {
		t.Errorf("expected true, got %s", val)
	}
}

func writeInitialState(s CookieStorer, w *httptest.ResponseRecorder, r *http.Request) (authboss.ClientState, error) {
	emptyState, err := s.ReadState(r)
	if err != nil {
		return nil, err
	}
	if val, ok := emptyState.Get("hello"); ok || len(val) != 0 {
		return nil, fmt.Errorf("it should not have had a value: %s", val)
	}
	put := []authboss.ClientStateEvent{{Kind: authboss.ClientStateEventPut, Key: "hello", Value: "World"}}
	if err := s.WriteState(w, emptyState, put); err != nil {
		return nil, err
	}
	state, err := s.ReadState(r)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func TestCookieExpiry(t *testing.T) {
	t.Parallel()

	storer := NewCookieStorer([]byte("key"), nil)
	storer.MaxAge = 1

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	_, err := writeInitialState(storer, w, r)
	if err != nil {
		t.Error(err)
	}

	w.Flush()

	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "Max-Age=1") {
		t.Error("max age should have been set")
	}

	time.Sleep(time.Second * 2)

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookie)
	state, err := storer.ReadState(r)
	if err != nil {
		t.Fatal(err)
	}

	if val, ok := state.Get("hello"); ok || len(val) != 0 {
		t.Error("it should not have had a value:", val)
	}
}

func TestCookiePutAndDelete(t *testing.T) {
	t.Parallel()

	storer := NewCookieStorer([]byte("key"), nil)

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	state, err := writeInitialState(storer, w, r)
	if err != nil {
		t.Fatal(err)
	}

	w.Flush()
	cookie := w.Header().Get("Set-Cookie")
	want := []string{"Path=/;", "Max-Age=2628000;", "HttpOnly", "Expires=", "hello=", "Secure"}
	for _, w := range want {
		if !strings.Contains(cookie, w) {
			t.Errorf("cookie did not include: %s", w)
		}
	}

	del := []authboss.ClientStateEvent{{Kind: authboss.ClientStateEventDel, Key: "hello", Value: "World"}}

	if err := storer.WriteState(w, state, del); err != nil {
		t.Fatal(err)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookie)
	state, err = storer.ReadState(r)
	if err != nil {
		t.Fatal(err)
	}

	if val, ok := state.Get("hello"); ok || len(val) != 0 {
		t.Error("it should not have had a value:", val)
	}
}
