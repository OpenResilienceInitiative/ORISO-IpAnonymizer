package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

var anonymizerID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func authResponse(t *testing.T, handler http.Handler, cookie *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/auth", nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/auth status is %d, want 200", response.StatusCode)
	}
	id := response.Header.Get("X-Anon-Id")
	if !anonymizerID.MatchString(id) {
		t.Fatal("/auth must return a UUID-shaped anonymous identifier")
	}
	cookies := response.Cookies()
	switch len(cookies) {
	case 0:
		return id, nil
	case 1:
		return id, cookies[0]
	default:
		t.Fatal("/auth returned more than one cookie")
		return "", nil
	}
}

func TestNewSessionReturnsIndependentIDsAndSecureCookies(t *testing.T) {
	handler := newHandler(sessionKey{1}, time.Now)
	first, cookie := authResponse(t, handler, nil)
	second, other := authResponse(t, handler, nil)
	if cookie == nil || other == nil || cookie.Value == other.Value || first == second {
		t.Fatal("independent sessions must get different cookies and IDs")
	}
	if cookie.Name != "anon-session" || cookie.Path != "/" || !cookie.HttpOnly || !cookie.Secure ||
		cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 1800 {
		t.Fatal("cookie lost its original name, lifetime or privacy attributes")
	}
}

func TestSessionWorksOnIndependentReplicasAndAfterRestart(t *testing.T) {
	key := sessionKey{1}
	first := newHandler(key, time.Now)
	second := newHandler(key, time.Now)
	id, cookie := authResponse(t, first, nil)
	for _, replica := range []http.Handler{second, newHandler(key, time.Now), first} {
		replayed, renewed := authResponse(t, replica, cookie)
		if replayed != id || renewed != nil {
			t.Fatal("a valid session must retain its ID across replicas and restarts")
		}
	}
}

func TestExpiredSessionCannotBeReused(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	handler := newHandler(sessionKey{1}, func() time.Time { return now })
	id, cookie := authResponse(t, handler, nil)
	now = now.Add(29 * time.Minute)
	if found, next := authResponse(t, handler, cookie); found != id || next != nil {
		t.Fatal("the session must work before its original expiry")
	}
	now = now.Add(time.Minute)
	if found, next := authResponse(t, handler, cookie); found == id || next == nil {
		t.Fatal("the expired cookie must start a new session")
	}
}

func TestInvalidSessionStartsANewSession(t *testing.T) {
	handler := newHandler(sessionKey{1}, time.Now)
	id, cookie := authResponse(t, handler, nil)
	data, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatal("issued cookie must use base64url")
	}
	data[len(data)-1] ^= 1
	altered := *cookie
	altered.Value = base64.RawURLEncoding.EncodeToString(data)
	legacy := &http.Cookie{Name: "anon-session", Value: "7cc7c586-8667-43c6-bbdc-9c194acd1427"}
	for _, check := range []struct {
		name   string
		cookie *http.Cookie
		target http.Handler
	}{
		{"altered", &altered, handler},
		{"legacy", legacy, handler},
		{"key rotated", cookie, newHandler(sessionKey{2}, time.Now)},
	} {
		t.Run(check.name, func(t *testing.T) {
			if found, next := authResponse(t, check.target, check.cookie); found == id || next == nil || next.Value == check.cookie.Value {
				t.Fatal("an invalid cookie must start a new independent session")
			}
		})
	}
}

func TestSessionKeyConfigurationRequires32BytesOfBase64(t *testing.T) {
	configured := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if key, err := parseSessionKey(configured); err != nil || key[0] != 1 {
		t.Fatal("the configured shared key could not be read")
	}
	for _, invalid := range []string{"", "not base64", "YQ==", configured + "\n"} {
		if _, err := parseSessionKey(invalid); err == nil {
			t.Fatal("invalid shared keys must be rejected")
		}
	}
}
