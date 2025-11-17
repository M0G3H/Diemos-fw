package main

import (
	"fmt"
	"time"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type Rule struct {
	ID     int
	Host   string
	Proto  string
	Port   string
	Action string
	DateModified string
}

func openRuleDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT NOT NULL,
		proto TEXT NOT NULL,
		port TEXT NOT NULL,
		action TEXT NOT NULL,
		dateModified TEXT NOT NULL
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

func ruleExists(db *sql.DB, rule *Rule) bool {
	qry := fmt.Sprintf("SELECT id FROM rules WHERE host=\"%s\" AND proto=\"%s\" AND port=\"%s\"", rule.Host, rule.Proto, rule.Port)
	rows, err := db.Query(qry)
	if err != nil {
                return false
        }
        defer rows.Close()

	for rows.Next() {
		return true
	}
	return false
}

func addRuleToDB(db *sql.DB, rule Rule) error {
	now := time.Now()
	formattedDate := now.Format("2006-01-02 15:04:05")
	stmt := `INSERT INTO rules (host, proto, port, action, dateModified) VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(stmt, rule.Host, rule.Proto, rule.Port, rule.Action, formattedDate)
	return err
}

func delRuleFromDB(db *sql.DB, rule Rule) error {
	stmt := `DELETE FROM rules WHERE host=? AND proto=? AND port=? AND action=?`
	_, err := db.Exec(stmt, rule.Host, rule.Proto, rule.Port, rule.Action)
	return err
}

func getAllRules(db *sql.DB) ([]Rule, error) {
	rows, err := db.Query(`SELECT id, host, proto, port, action, dateModified FROM rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Host, &r.Proto, &r.Port, &r.Action, &r.DateModified); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

