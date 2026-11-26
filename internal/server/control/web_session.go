package control

import (
	"crypto/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	adminSessionLifetime = 8 * time.Hour
	adminSessionIdle     = 2 * time.Hour
	maxAdminSessions     = 64
	loginWindow          = time.Minute
	loginAttemptsAllowed = 5
	maxLoginClients      = 4096
	maxPasswordWorkers   = 2 // Argon2id uses 64 MiB per worker.
)

type webSession struct {
	csrf       string
	passwordAt time.Time
	lastSeen   time.Time
	expires    time.Time
	remote     string
}

type webSessions struct {
	mu   sync.Mutex
	live map[string]webSession
}

func (s *webSessions) create(now, passwordAt time.Time, remote string) (string, webSession) {
	id := rand.Text()
	session := webSession{csrf: rand.Text(), passwordAt: passwordAt, lastSeen: now, expires: now.Add(adminSessionLifetime), remote: remote}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldestID := ""
	var oldest time.Time
	for id, current := range s.live {
		if !s.validLocked(current, now) {
			delete(s.live, id)
		} else if oldestID == "" || current.lastSeen.Before(oldest) {
			oldestID, oldest = id, current.lastSeen
		}
	}
	if len(s.live) >= maxAdminSessions {
		delete(s.live, oldestID)
	}
	s.live[id] = session
	return id, session
}

func (s *webSessions) validLocked(session webSession, now time.Time) bool {
	return now.Before(session.expires) && now.Sub(session.lastSeen) < adminSessionIdle
}

// get returns a live session for the exact password generation that was verified.
func (s *webSessions) get(id string, now, passwordAt time.Time) (webSession, bool) {
	if id == "" {
		return webSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.live[id]
	if !ok {
		return webSession{}, false
	}
	if !s.validLocked(session, now) || !session.passwordAt.Equal(passwordAt) {
		delete(s.live, id)
		return webSession{}, false
	}
	session.lastSeen = now
	s.live[id] = session
	return session, true
}

func (s *webSessions) revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, id)
}

// loginLimiter reserves a per-client attempt and a global worker before
// starting a slow password operation. It never waits for a hashing slot.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginWindowState
	inFlight int
}

type loginWindowState struct {
	until time.Time
	count int
}

func (l *loginLimiter) reserve(remote string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight >= maxPasswordWorkers {
		return false
	}
	if l.attempts == nil {
		l.attempts = make(map[string]loginWindowState)
	}
	key := clientKey(remote)
	entry, exists := l.attempts[key]
	if !exists && len(l.attempts) >= maxLoginClients {
		for k, v := range l.attempts {
			if !now.Before(v.until) {
				delete(l.attempts, k)
			}
		}
		if len(l.attempts) >= maxLoginClients {
			return false
		}
	}
	if !now.Before(entry.until) {
		entry = loginWindowState{until: now.Add(loginWindow)}
	}
	if entry.count >= loginAttemptsAllowed {
		return false
	}
	entry.count++
	l.attempts[key] = entry
	l.inFlight++
	return true
}

func (l *loginLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inFlight--
}

func clientKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func adminCookie(r *http.Request) http.Cookie {
	c := http.Cookie{
		Name: "acktier_admin", Path: "/admin/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
	if r.TLS != nil {
		c.Name = "__Host-acktier-admin"
		c.Path = "/"
		c.Secure = true
	}
	return c
}

func adminSessionID(r *http.Request) string {
	name := adminCookie(r).Name
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// Do not send login credentials or cookies over remote plain HTTP, even if
// the operator has enabled insecure HTTP for the node API. Check the Host
// as well as the connection to restrict the loopback exception.
func adminTransportOK(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !isLoopbackIP(remoteHost) {
		return false
	}
	host := (&url.URL{Host: r.Host}).Hostname()
	return strings.EqualFold(host, "localhost") || isLoopbackIP(host)
}

func isLoopbackIP(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}
