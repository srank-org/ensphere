package sysmap

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// committedRepo is a repository with two tracked files and one commit.
func committedRepo(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	git(t, root, "init", "-q")
	writeFile(t, root, "routes/otp.ts", "v1\n")
	writeFile(t, root, "db/schema.sql", "v1\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "base")
	return root, git(t, root, "rev-parse", "HEAD")
}

func TestReadSourceStateOutsideGit(t *testing.T) {
	state, err := ReadSourceState(t.TempDir())
	if err != nil {
		t.Fatalf("ReadSourceState: %v", err)
	}
	if state.Git || state.Commit != "" || !state.Clean() {
		t.Fatalf("a directory outside git must report Git false and nothing else, got %+v", state)
	}
}

func TestReadSourceStateReportsCommitAndDrift(t *testing.T) {
	root, head := committedRepo(t)
	state, err := ReadSourceState(root)
	if err != nil {
		t.Fatalf("ReadSourceState: %v", err)
	}
	if !state.Git || state.Commit != head || !state.Clean() || len(state.Untracked) != 0 {
		t.Fatalf("a clean checkout must report its commit and no drift, got %+v", state)
	}

	writeFile(t, root, "routes/otp.ts", "v2\n")
	writeFile(t, root, "routes/new.ts", "new\n")
	writeFile(t, root, ".ensphere/surfaces.yaml", "version: 1\n")
	writeFile(t, root, "ensphere-pentest/config.md", "# Config\n")
	writeFile(t, root, "my-workspace/progress.md", "x\n")
	state, err = ReadSourceState(root, "my-workspace")
	if err != nil {
		t.Fatalf("ReadSourceState: %v", err)
	}
	if state.Clean() || !reflect.DeepEqual(state.Modified, []string{"routes/otp.ts"}) {
		t.Fatalf("expected routes/otp.ts modified, got %+v", state)
	}
	if !reflect.DeepEqual(state.Untracked, []string{"routes/new.ts"}) {
		t.Fatalf("Ensphere's files and the named workspace must not count as untracked, got %+v", state.Untracked)
	}

	if err := os.Remove(filepath.Join(root, "db", "schema.sql")); err != nil {
		t.Fatal(err)
	}
	state, err = ReadSourceState(root)
	if err != nil {
		t.Fatalf("ReadSourceState: %v", err)
	}
	if !reflect.DeepEqual(state.Modified, []string{"db/schema.sql", "routes/otp.ts"}) {
		t.Fatalf("a deleted tracked file is a modification, got %+v", state.Modified)
	}
}
