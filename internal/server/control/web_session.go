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
	maxAdminSessions     = 64
)

type webSession struct {
	csrf    string
	expires time.Time
}

type webSessions struct {
	mu   sync.Mutex
	live map[string]webSession
}

func (s *webSessions) create(now time.Time) (string, webSession) {
	id := rand.Text()
	session := webSession{csrf: rand.Text(), expires: now.Add(adminSessionLifetime)}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldestID := ""
	var oldest time.Time
	for id, current := range s.live {
		if !now.Before(current.expires) {
			delete(s.live, id)
		} else if oldestID == "" || current.expires.Before(oldest) {
			oldestID, oldest = id, current.expires
		}
	}
	if len(s.live) >= maxAdminSessions {
		delete(s.live, oldestID)
	}
	s.live[id] = session
	return id, session
}

func (s *webSessions) get(id string, now time.Time) (webSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.live[id]
	if ok && !now.Before(session.expires) {
		delete(s.live, id)
		return webSession{}, false
	}
	return session, ok
}

func (s *webSessions) revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, id)
}

func adminCookie(r *http.Request) http.Cookie {
	c := http.Cookie{
		Name: "acktier_admin", Path: "/admin/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
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
