package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/acktier/acktier/internal/secfile"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const sqliteApplicationID = 0x41434b54 // "ACKT"

var ErrCenterInUse = errors.New("center database is in use; stop the running center before opening it offline")

type sqliteState struct {
	db   *sql.DB
	conn *sql.Conn
}

// OpenExistingFileStore opens a stopped center's database without creating
// one. Like NewFileStore, it takes an exclusive lock for its lifetime.
func OpenExistingFileStore(path string) (*FileStore, error) {
	return openSQLite(path, true)
}

func openSQLite(path string, existingOnly bool) (_ *FileStore, err error) {
	if path == "" {
		return nil, errors.New("a persistent SQLite database path is required")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return nil, err
	}
	if fresh && existingOnly {
		return nil, fmt.Errorf("center database %s does not exist; start the center first", path)
	}
	if !fresh && info.Size() == 0 {
		return nil, fmt.Errorf("center database %s is empty; refusing to overwrite it", path)
	}
	if err := secfile.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := secfile.CheckPrivateFile(path + suffix); err != nil && !os.IsNotExist(err) {
			return nil, err
		} else if fresh && err == nil {
			return nil, fmt.Errorf("database %s is missing but its journal exists; recover the database before starting", path)
		}
	}
	// SQLite's journals inherit directory permissions. Create the main file
	// ourselves so its permissions are also private on Unix.
	if fresh {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if os.IsExist(err) {
			return nil, ErrCenterInUse
		}
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	if err := secfile.CheckPrivateFile(path); err != nil {
		return nil, err
	}
	b, err := connectSQLite(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = b.close()
		}
	}()
	st := &FileStore{data: emptySnapshot()}
	if err := b.openStore(st, fresh); err != nil {
		return nil, sqliteError(err)
	}
	st.sqlite = b
	return st, nil
}

func connectSQLite(path string) (*sqliteState, error) {
	uri := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && path[1] == ':' {
		uri = "/" + uri
	}
	u := url.URL{Scheme: "file", Path: uri}
	u.RawQuery = url.Values{
		"mode":          {"rw"},
		"_busy_timeout": {"1000"},
		"_txlock":       {"exclusive"},
		"_pragma":       {"locking_mode(EXCLUSIVE)", "synchronous(FULL)", "temp_store(MEMORY)"},
	}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, sqliteError(err)
	}
	return &sqliteState{db: db, conn: conn}, nil
}

func sqliteError(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) && (se.Code()&0xff == sqlite3.SQLITE_BUSY || se.Code()&0xff == sqlite3.SQLITE_LOCKED) {
		return fmt.Errorf("%w: %v", ErrCenterInUse, err)
	}
	return err
}

func (b *sqliteState) close() error {
	return errors.Join(b.conn.Close(), b.db.Close())
}

// Close releases the database's exclusive lock. It is a no-op for memory stores.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sqlite == nil || s.sqlite.conn == nil {
		return nil
	}
	err := s.sqlite.close()
	s.sqlite.conn = nil
	return err
}

func (b *sqliteState) transact(run func(*sql.Tx) error) error {
	if b.conn == nil {
		return errors.New("center database is closed")
	}
	tx, err := b.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := run(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *sqliteState) openStore(st *FileStore, fresh bool) error {
	return b.transact(func(tx *sql.Tx) error {
		var applicationID int
		if err := tx.QueryRow("PRAGMA application_id").Scan(&applicationID); err != nil {
			return err
		}
		if !fresh {
			if applicationID != sqliteApplicationID {
				return errors.New("not an AckTier center database")
			}
			return readSQLite(tx, st)
		}
		if _, err := tx.Exec(sqliteSchema); err != nil {
			return err
		}
		if err := initSQLiteSettings(tx, &st.data); err != nil {
			return err
		}
		_, err := tx.Exec(fmt.Sprintf("PRAGMA application_id=%d", sqliteApplicationID))
		return err
	})
}
