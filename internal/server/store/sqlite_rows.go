package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ackwrap/acktier/pkg/types"
)

// JSON encodes individual structured records, not the database. Each heartbeat
// touches one node row. Authorization payload/signature bytes are never re-signed.
const sqliteSchema = `
CREATE TABLE settings (name TEXT PRIMARY KEY, record BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TABLE nodes (
    id TEXT PRIMARY KEY, machine_key TEXT NOT NULL UNIQUE, node_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE, record BLOB NOT NULL
) WITHOUT ROWID, STRICT;
CREATE TABLE pre_auth_keys (id TEXT PRIMARY KEY, record BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TABLE retired_keys (id TEXT PRIMARY KEY) WITHOUT ROWID, STRICT;
CREATE TABLE drafts (id TEXT PRIMARY KEY, record BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TABLE inventory (id TEXT PRIMARY KEY, record BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TABLE publications (id TEXT PRIMARY KEY, record BLOB NOT NULL) WITHOUT ROWID, STRICT;
CREATE TABLE audit (seq INTEGER PRIMARY KEY, record BLOB NOT NULL) STRICT;
`

type unsignedPolicyState struct {
	ACLPolicy   types.ACLPolicy    `json:"aclPolicy"`
	FilterRules []types.FilterRule `json:"filterRules,omitempty"`
	DNS         types.DNSConfig    `json:"dns"`
}

func unsignedPolicyOf(s *snapshot) unsignedPolicyState {
	return unsignedPolicyState{s.ACLPolicy, s.FilterRules, s.DNS}
}

func sqliteRecord(tx *sql.Tx, table, id string, value any) error {
	idColumn := "id"
	if table == "settings" {
		idColumn = "name"
	}
	// Table and column names are fixed by the store, not derived from requests.
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO "+table+" ("+idColumn+", record) VALUES (?, ?) "+
		"ON CONFLICT("+idColumn+") DO UPDATE SET record=excluded.record", id, raw)
	return err
}

func sqliteDelete(tx *sql.Tx, table, id string) error {
	_, err := tx.Exec("DELETE FROM "+table+" WHERE id=?", id)
	return err
}

func saveSQLiteRecord[T any](tx *sql.Tx, table, id string, records map[string]T) error {
	record, ok := records[id]
	if !ok {
		return sqliteDelete(tx, table, id)
	}
	return sqliteRecord(tx, table, id, record)
}

func sqliteNode(tx *sql.Tx, record StoredNode) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	n := record.Node
	_, err = tx.Exec(`INSERT INTO nodes (id,machine_key,node_key,name,record) VALUES (?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET machine_key=excluded.machine_key,node_key=excluded.node_key,name=excluded.name,record=excluded.record`,
		strconv.FormatUint(uint64(n.ID), 10), n.MachineKey.String(), n.NodeKey.String(), n.Name, raw)
	return err
}

func sqliteAudit(tx *sql.Tx, entries []AuditEntry) error {
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO audit(record) VALUES (?)", raw); err != nil {
			return err
		}
	}
	if len(entries) != 0 {
		_, err := tx.Exec("DELETE FROM audit WHERE seq <= (SELECT seq FROM audit ORDER BY seq DESC LIMIT 1 OFFSET ?)", maxAuditEntries)
		return err
	}
	return nil
}

func (b *sqliteState) save(data *snapshot, c stateChange) error {
	return b.transact(func(tx *sql.Tx) error {
		for _, row := range []struct {
			write bool
			name  string
			value any
		}{
			{c.nextID, "nextNodeId", data.NextNodeID},
			{c.owner, "owner", data.Owner},
			{c.unsignedPolicy, "unsignedPolicy", unsignedPolicyOf(data)},
			{c.password, "adminPassword", data.AdminPassword},
			{c.delegation, "delegation", data.Delegation},
		} {
			if row.write {
				if err := sqliteRecord(tx, "settings", row.name, row.value); err != nil {
					return err
				}
			}
		}
		if c.node != 0 {
			if node, ok := data.Nodes[c.node]; ok {
				if err := sqliteNode(tx, node); err != nil {
					return err
				}
			} else if err := sqliteDelete(tx, "nodes", strconv.FormatUint(uint64(c.node), 10)); err != nil {
				return err
			}
		}
		if c.key != "" {
			if err := saveSQLiteRecord(tx, "pre_auth_keys", c.key, data.PreAuthKeys); err != nil {
				return err
			}
		}
		if c.retiredKey != "" {
			if _, err := tx.Exec("INSERT OR IGNORE INTO retired_keys(id) VALUES (?)", c.retiredKey); err != nil {
				return err
			}
		}
		if c.draft != "" {
			if err := saveSQLiteRecord(tx, "drafts", c.draft, data.Drafts); err != nil {
				return err
			}
		}
		if c.inventory != "" {
			if err := saveSQLiteRecord(tx, "inventory", c.inventory, data.Inventory); err != nil {
				return err
			}
		}
		if c.publication != nil {
			if err := sqliteRecord(tx, "publications", versionID(c.publication.Version), c.publication); err != nil {
				return err
			}
		}
		if c.prunedVersion != 0 {
			if _, err := tx.Exec("DELETE FROM publications WHERE id <= ?", versionID(c.prunedVersion)); err != nil {
				return err
			}
		}
		return sqliteAudit(tx, c.audit)
	})
}

func versionID(version uint64) string {
	// Text preserves the full uint64 range and sorts numerically when padded.
	return fmt.Sprintf("%020d", version)
}

func initSQLiteSettings(tx *sql.Tx, data *snapshot) error {
	for _, row := range []struct {
		name  string
		value any
	}{
		{"nextNodeId", data.NextNodeID}, {"owner", data.Owner}, {"unsignedPolicy", unsignedPolicyOf(data)},
		{"adminPassword", data.AdminPassword}, {"delegation", data.Delegation},
	} {
		if err := sqliteRecord(tx, "settings", row.name, row.value); err != nil {
			return err
		}
	}
	return nil
}

func readSQLite(tx *sql.Tx, st *FileStore) error {
	data := &st.data
	var unsigned unsignedPolicyState
	for _, row := range []struct {
		name string
		dst  any
	}{
		{"nextNodeId", &data.NextNodeID}, {"owner", &data.Owner}, {"unsignedPolicy", &unsigned},
		{"adminPassword", &data.AdminPassword}, {"delegation", &data.Delegation},
	} {
		var raw []byte
		if err := tx.QueryRow("SELECT record FROM settings WHERE name=?", row.name).Scan(&raw); err != nil {
			return fmt.Errorf("read center setting %s: %w", row.name, err)
		}
		if err := json.Unmarshal(raw, row.dst); err != nil {
			return fmt.Errorf("invalid center setting %s", row.name)
		}
	}
	data.ACLPolicy, data.FilterRules, data.DNS = unsigned.ACLPolicy, unsigned.FilterRules, unsigned.DNS

	nodes, err := readMap[StoredNode](tx, "nodes")
	if err != nil {
		return err
	}
	for id, node := range nodes {
		if id != strconv.FormatUint(uint64(node.Node.ID), 10) {
			return errors.New("invalid stored node ID")
		}
		data.Nodes[node.Node.ID] = node
	}
	if data.PreAuthKeys, err = readMap[storedAuthKey](tx, "pre_auth_keys"); err != nil {
		return err
	}
	if data.Drafts, err = readMap[Draft](tx, "drafts"); err != nil {
		return err
	}
	if data.Inventory, err = readMap[Inventory](tx, "inventory"); err != nil {
		return err
	}
	if err := readRows(tx, "retired_keys", "SELECT id, NULL FROM retired_keys", func(id string, _ []byte) error {
		data.RetiredKeys[id] = true
		return nil
	}); err != nil {
		return err
	}
	if err := readRows(tx, "publications", "SELECT id, record FROM publications ORDER BY id", func(id string, raw []byte) error {
		var rec PublicationRecord
		if err := json.Unmarshal(raw, &rec); err != nil || id != versionID(rec.Version) {
			return errors.New("invalid publication record")
		}
		data.Publications = append(data.Publications, rec)
		return nil
	}); err != nil {
		return err
	}
	if err := readRows(tx, "audit", "SELECT '', record FROM audit ORDER BY seq", func(_ string, raw []byte) error {
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return errors.New("invalid audit record")
		}
		data.Audit = append(data.Audit, e)
		return nil
	}); err != nil {
		return err
	}
	return st.validatePersistentState()
}

func readMap[T any](tx *sql.Tx, table string) (map[string]T, error) {
	out := make(map[string]T)
	err := readRows(tx, table, "SELECT id, record FROM "+table, func(id string, raw []byte) error {
		var record T
		if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" || json.Unmarshal(raw, &record) != nil {
			return errors.New("invalid record")
		}
		out[id] = record
		return nil
	})
	return out, err
}

func readRows(tx *sql.Tx, table, query string, read func(string, []byte) error) error {
	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		if err := read(id, raw); err != nil {
			return fmt.Errorf("read center table %s: %w", table, err)
		}
	}
	return rows.Err()
}
