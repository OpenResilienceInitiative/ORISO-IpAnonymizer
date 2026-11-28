package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// drainDelay keeps a stopping pod answering while Kubernetes removes it from the
// Service endpoints; shutdownTimeout bounds the wait for requests in flight.
// Together they stay inside the default 30s termination grace period.
const (
	drainDelay      = 5 * time.Second
	shutdownTimeout = 10 * time.Second
)

const (
	cookieName        = "anon-session"
	sessionTTL        = 30 * time.Minute
	cookieVersion     = 1
	cookieNonceOffset = 1 + 8 // version byte followed by the big-endian expiry
	cookiePayloadSize = cookieNonceOffset + 16
)

type sessionKey [sha256.Size]byte

func parseSessionKey(value string) (sessionKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != sha256.Size || base64.StdEncoding.EncodeToString(key) != value {
		return sessionKey{}, fmt.Errorf("ANON_SESSION_KEY must be a base64-encoded 32-byte key")
	}
	return sessionKey(key), nil
}

func (key sessionKey) digest(domain string, data []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(domain))
	mac.Write(data)
	return mac.Sum(nil)
}

func (key sessionKey) cookiePayload(value string, now time.Time) []byte {
	if len(value) != base64.RawURLEncoding.EncodedLen(cookiePayloadSize+sha256.Size) {
		return nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != cookiePayloadSize+sha256.Size || decoded[0] != cookieVersion {
		return nil
	}
	payload, signature := decoded[:cookiePayloadSize], decoded[cookiePayloadSize:]
	if !hmac.Equal(signature, key.digest("anon-session/v1\x00", payload)) {
		return nil
	}
	expiry := int64(binary.BigEndian.Uint64(payload[1:cookieNonceOffset]))
	if now.Unix() >= expiry {
		return nil
	}
	return payload
}

func (key sessionKey) newCookie(w http.ResponseWriter, now time.Time) []byte {
	payload := make([]byte, cookiePayloadSize, cookiePayloadSize+sha256.Size)
	payload[0] = cookieVersion
	binary.BigEndian.PutUint64(payload[1:cookieNonceOffset], uint64(now.Add(sessionTTL).Unix()))
	rand.Read(payload[cookieNonceOffset:])
	signed := append(payload, key.digest("anon-session/v1\x00", payload)...)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    base64.RawURLEncoding.EncodeToString(signed),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   int(sessionTTL.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})
	return payload
}

func (key sessionKey) anonymousID(nonce []byte) string {
	id := key.digest("anon-id/v1\x00", nonce)[:16]
	id[6] = (id[6] & 0x0f) | 0x80 // UUIDv8, application-defined contents
	id[8] = (id[8] & 0x3f) | 0x80 // RFC UUID variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

func newHandler(key sessionKey, clock func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		now := clock()
		var payload []byte
		if cookie, err := r.Cookie(cookieName); err == nil {
			payload = key.cookiePayload(cookie.Value, now)
		}
		if payload == nil {
			payload = key.newCookie(w, now)
		}
		w.Header().Set("X-Anon-Id", key.anonymousID(payload[cookieNonceOffset:]))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// serve runs server until ctx is cancelled, then keeps serving for delay before
// shutting down: endpoint removal lags SIGTERM, and every ingress request waits
// on /auth, so exiting at once fails requests that are still routed here.
func serve(ctx context.Context, server *http.Server, listener net.Listener, delay time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	time.Sleep(delay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func main() {
	key, err := parseSessionKey(os.Getenv("ANON_SESSION_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := serve(ctx, &http.Server{Handler: newHandler(key, time.Now)}, listener, drainDelay); err != nil {
		log.Fatal(err)
	}
}
