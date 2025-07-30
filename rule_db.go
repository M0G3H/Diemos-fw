package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type Rule struct {
	ID     int
	Host   string
	Proto  string
	Port   string
	Action string
}

func openRuleDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Initialize table if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT NOT NULL,
		proto TEXT NOT NULL,
		port TEXT NOT NULL,
		action TEXT NOT NULL
	)`)

	if err != nil {
		return db, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS defaults (
		id INTEGER PRIMARY KEY CHECK (id = 0),
		all_policy TEXT NOT NULL CHECK (all_policy IN ('allow', 'deny'))
	)`)

	return db, err
}

func getDefaultPolicyFromDB(db *sql.DB) (string, error) {
	var policy string
	err := db.QueryRow(`SELECT all_policy FROM defaults WHERE id = 0`).Scan(&policy)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return policy, err
}

func setDefaultPolicyInDB(db *sql.DB, policy string) error {
	// Replace or insert the single row
	stmt := `INSERT INTO defaults (id, all_policy) VALUES (0, ?)
	         ON CONFLICT(id) DO UPDATE SET all_policy=excluded.all_policy`
	_, err := db.Exec(stmt, policy)
	return err
}


func addRuleToDB(db *sql.DB, rule Rule) error {
	stmt := `INSERT INTO rules (host, proto, port, action) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(stmt, rule.Host, rule.Proto, rule.Port, rule.Action)
	return err
}

func delRuleFromDB(db *sql.DB, rule Rule) error {
	stmt := `DELETE FROM rules WHERE host=? AND proto=? AND port=? AND action=?`
	_, err := db.Exec(stmt, rule.Host, rule.Proto, rule.Port, rule.Action)
	return err
}

func getAllRules(db *sql.DB) ([]Rule, error) {
	rows, err := db.Query(`SELECT id, host, proto, port, action FROM rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Host, &r.Proto, &r.Port, &r.Action); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}
