package store

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinAdminPasswordLen = 12
	maxAdminPasswordLen = 256
)

var (
	ErrWeakPassword    = errors.New("store: admin password needs at least 12 characters and at most 256 bytes")
	ErrPasswordChanged = errors.New("store: admin password has changed")
)

// PasswordHash stores an Argon2id hash with its parameters. The plaintext is
// never persisted.
type PasswordHash struct {
	Salt      []byte    `json:"salt"`
	Hash      []byte    `json:"hash"`
	Time      uint32    `json:"time"`
	Memory    uint32    `json:"memoryKiB"`
	Threads   uint8     `json:"threads"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func hashPassword(password string) PasswordHash {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	p := PasswordHash{Salt: salt, Time: 2, Memory: 64 * 1024, Threads: 2}
	p.Hash = argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, 32)
	return p
}

func (p PasswordHash) valid() bool {
	return len(p.Salt) == 16 && len(p.Hash) == 32 && p.Time == 2 && p.Memory == 64*1024 && p.Threads == 2 && !p.UpdatedAt.IsZero()
}

func (p PasswordHash) matches(password string) bool {
	if !p.valid() {
		return false
	}
	got := argon2.IDKey([]byte(password), p.Salt, p.Time, p.Memory, p.Threads, uint32(len(p.Hash)))
	return subtle.ConstantTimeCompare(got, p.Hash) == 1
}

func validPassword(password string) bool {
	n := utf8.RuneCountInString(password)
	return utf8.ValidString(password) && n >= MinAdminPasswordLen && len(password) <= maxAdminPasswordLen
}

// SetAdminPassword replaces the Web administrator password. Callers must
// revoke existing sessions; AdminPasswordUpdatedAt changes for that purpose.
func (s *FileStore) SetAdminPassword(password string, audit ...AuditEntry) error {
	_, err := s.setAdminPassword(password, nil, audit...)
	return err
}

// RotateAdminPassword only replaces the generation the caller authenticated.
func (s *FileStore) RotateAdminPassword(password string, previous time.Time, audit ...AuditEntry) (time.Time, error) {
	return s.setAdminPassword(password, &previous, audit...)
}

func (s *FileStore) setAdminPassword(password string, previous *time.Time, audit ...AuditEntry) (time.Time, error) {
	if !validPassword(password) {
		return time.Time{}, ErrWeakPassword
	}
	next := hashPassword(password)
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data.AdminPassword
	if previous != nil && (prev == nil || !prev.UpdatedAt.Equal(*previous)) {
		return time.Time{}, ErrPasswordChanged
	}
	next.UpdatedAt = time.Now().UTC()
	if prev != nil && !next.UpdatedAt.After(prev.UpdatedAt) {
		next.UpdatedAt = prev.UpdatedAt.Add(time.Nanosecond)
	}
	s.data.AdminPassword = &next
	if err := s.commitLocked(stateChange{password: true}, audit...); err != nil {
		s.data.AdminPassword = prev
		return time.Time{}, err
	}
	return next.UpdatedAt, nil
}

func (s *FileStore) HasAdminPassword() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.AdminPassword != nil
}

// AdminPasswordUpdatedAt reports when the password last changed; sessions
// created before that instant are no longer valid.
func (s *FileStore) AdminPasswordUpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.AdminPassword == nil {
		return time.Time{}
	}
	return s.data.AdminPassword.UpdatedAt
}

func (s *FileStore) VerifyAdminPassword(password string) bool {
	_, ok := s.CheckAdminPassword(password)
	return ok
}

// CheckAdminPassword returns the generation actually verified, even if a
// password rotation happened while the slow hash ran outside the store lock.
func (s *FileStore) CheckAdminPassword(password string) (time.Time, bool) {
	s.mu.RLock()
	stored := s.data.AdminPassword
	s.mu.RUnlock()
	if stored == nil || len(password) > maxAdminPasswordLen {
		return time.Time{}, false
	}
	return stored.UpdatedAt, stored.matches(password)
}
