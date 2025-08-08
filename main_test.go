package main

import (
    "database/sql"
    "testing"

    _ "github.com/mattn/go-sqlite3"
)

func TestInitDB(t *testing.T) {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        t.Fatal(err)
    }
    if err := initDB(db); err != nil {
        t.Fatalf("initDB: %v", err)
    }
}

