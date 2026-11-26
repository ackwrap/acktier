package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultCenterDB = "./data/center/server.sqlite"

// Don't let the generated credentials file replace a database, its journals,
// or the operator's password source.
func distinctStatePaths(db, credentials, passwordFile string) error {
	protected := []string{passwordFile}
	if db != "" {
		protected = append(protected, db, db+"-journal", db+"-wal", db+"-shm")
	}
	normalize := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		if physical, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
			return filepath.Join(physical, filepath.Base(abs))
		}
		return abs
	}
	path := normalize(credentials)
	info, _ := os.Stat(path)
	for _, p := range protected {
		if p == "" {
			continue
		}
		other := normalize(p)
		otherInfo, _ := os.Stat(other)
		if strings.EqualFold(path, other) || (info != nil && otherInfo != nil && os.SameFile(info, otherInfo)) {
			return fmt.Errorf("credentials file must be separate from state and password sources: %s", credentials)
		}
	}
	return nil
}
