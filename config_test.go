package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigExpandsEnvVars(t *testing.T) {
	t.Setenv("MY_SECRET", "hunter2")
	f := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(f, []byte(`{"TYPE": "MYTHICBEASTS", "secret": "$MY_SECRET"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if c["TYPE"] != "MYTHICBEASTS" || c["secret"] != "hunter2" {
		t.Errorf("config = %v", c)
	}
}

func TestLoadConfigRejectsBadJSON(t *testing.T) {
	f := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(f, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(f); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}
