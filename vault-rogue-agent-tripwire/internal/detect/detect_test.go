package detect_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/detect"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/event"
)

var (
	evalPattern = regexp.MustCompile(`^eval-[a-z0-9-]+$`)
	kvMounts    = []string{"kv"}
	decoys      = []string{"kv/research/artifactory-admin"}
)

// makeEvent is a helper that builds an Event with sensible defaults.
func makeEvent(evType, path, operation, entityID, role, requestID string) event.Event {
	md := map[string]string{}
	if role != "" {
		md["role"] = role
	}
	if len(md) == 0 {
		md = nil
	}
	return event.Event{
		Type:      evType,
		Time:      time.Now(),
		RequestID: requestID,
		Path:      path,
		Operation: operation,
		EntityID:  entityID,
		Metadata:  md,
	}
}

// loadAuditFile parses a testdata/audit/*.json file into an event.Event.
// It exercises the full parse path to ensure real captured lines work.
func loadAuditFile(t *testing.T, name string) event.Event {
	t.Helper()
	data, err := os.ReadFile("../../testdata/audit/" + name)
	if err != nil {
		t.Skipf("testdata file not found (%s): %v", name, err)
	}
	// Compact to a single line (the file is pretty-printed for readability).
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON in %s: %v", name, err)
	}
	compact, _ := json.Marshal(raw)
	ev, err := event.Parse(compact)
	if err != nil {
		t.Fatalf("event.Parse(%s): %v", name, err)
	}
	return ev
}

// ── NormalizeKVPath is tested in event/normalize_test.go ──────────────────

func TestDecoyDetector_SevKill(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	// eval role + entity ID + decoy path (via data/ sub-path)
	ev := makeEvent("request", "kv/data/research/artifactory-admin", "read",
		"entity-uuid-1", "eval-0412", "req-kill-1")
	findings := d.Inspect(ev)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != detect.SevKill {
		t.Errorf("Severity = %v, want SevKill", findings[0].Severity)
	}
}

func TestDecoyDetector_SevPage_NonEvalRole(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	// non-eval role (e.g. admin) — alert only, no kill
	ev := makeEvent("request", "kv/data/research/artifactory-admin", "read",
		"entity-uuid-2", "admin", "req-page-1")
	findings := d.Inspect(ev)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != detect.SevPage {
		t.Errorf("Severity = %v, want SevPage", findings[0].Severity)
	}
}

func TestDecoyDetector_SevPage_EmptyEntity(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	// eval role match but no entity ID → SevPage, not SevKill
	ev := makeEvent("request", "kv/data/research/artifactory-admin", "read",
		"", "eval-0412", "req-page-2")
	findings := d.Inspect(ev)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != detect.SevPage {
		t.Errorf("Severity = %v, want SevPage (empty entity)", findings[0].Severity)
	}
}

func TestDecoyDetector_NoMatch_NonDecoyPath(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	ev := makeEvent("request", "kv/data/evals/0412/task", "read",
		"entity-uuid-3", "eval-0412", "req-no-1")
	findings := d.Inspect(ev)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-decoy path, got %d", len(findings))
	}
}

func TestDecoyDetector_NoMatch_ResponseEntry(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	// response type — detector must only fire on request entries
	ev := makeEvent("response", "kv/data/research/artifactory-admin", "read",
		"entity-uuid-4", "eval-0412", "req-resp-1")
	findings := d.Inspect(ev)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for response entry, got %d", len(findings))
	}
}

func TestDecoyDetector_Dedup_SameRequestID(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	ev := makeEvent("request", "kv/data/research/artifactory-admin", "read",
		"entity-uuid-5", "eval-0412", "req-dup-1")

	f1 := d.Inspect(ev)
	f2 := d.Inspect(ev) // same request ID

	if len(f1) != 1 {
		t.Fatalf("first inspect: expected 1 finding, got %d", len(f1))
	}
	if len(f2) != 0 {
		t.Errorf("second inspect (dup): expected 0 findings, got %d (dedup failed)", len(f2))
	}
}

func TestDecoyDetector_NoDedup_DifferentRequestID(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	ev1 := makeEvent("request", "kv/data/research/artifactory-admin", "read",
		"entity-uuid-6", "eval-0412", "req-a")
	ev2 := makeEvent("request", "kv/data/research/artifactory-admin", "read",
		"entity-uuid-6", "eval-0412", "req-b") // different request ID

	f1 := d.Inspect(ev1)
	f2 := d.Inspect(ev2)

	if len(f1) != 1 || len(f2) != 1 {
		t.Errorf("expected 1 finding each; got %d and %d", len(f1), len(f2))
	}
}

func TestDecoyDetector_AllKVSubpaths(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	subpaths := []string{"data", "metadata", "delete", "undelete", "destroy"}
	for i, sub := range subpaths {
		ev := makeEvent("request",
			"kv/"+sub+"/research/artifactory-admin", "read",
			"entity-uuid-7", "eval-0412", fmt.Sprintf("req-sub-%d", i))
		findings := d.Inspect(ev)
		if len(findings) != 1 {
			t.Errorf("sub-path %q: expected 1 finding, got %d", sub, len(findings))
		} else if findings[0].Severity != detect.SevKill {
			t.Errorf("sub-path %q: Severity = %v, want SevKill", sub, findings[0].Severity)
		}
	}
}

func TestDecoyDetector_ParentListNoMatch(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	// list on parent — kv/metadata/research/ normalizes to kv/research/
	// which does NOT equal kv/research/artifactory-admin
	ev := makeEvent("request", "kv/metadata/research/", "list",
		"entity-uuid-8", "eval-0412", "req-list-1")
	findings := d.Inspect(ev)
	if len(findings) != 0 {
		t.Errorf("parent list: expected 0 findings, got %d", len(findings))
	}
}

func TestDecoyDetector_NonKVPath(t *testing.T) {
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)

	// sys/health — not a KV path, can never match a decoy
	ev := makeEvent("request", "sys/health", "read",
		"entity-uuid-9", "eval-0412", "req-sys-1")
	findings := d.Inspect(ev)
	if len(findings) != 0 {
		t.Errorf("non-KV path: expected 0 findings, got %d", len(findings))
	}
}

// TestDecoyDetector_RealAuditLine_NormalRead loads a real captured audit line
// and confirms a normal (admin) read produces SevPage.
func TestDecoyDetector_RealAuditLine_NormalRead(t *testing.T) {
	ev := loadAuditFile(t, "normal-read-request.json")
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)
	findings := d.Inspect(ev)
	// The real line's path is kv/data/research/artifactory-admin — should match.
	// The root token has no metadata["role"], so should be SevPage.
	if ev.Path == "kv/data/research/artifactory-admin" {
		if len(findings) != 1 {
			t.Fatalf("real line: expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != detect.SevPage {
			t.Errorf("real line: Severity = %v, want SevPage (root token, no eval role)", findings[0].Severity)
		}
	}
	// If the captured line is for a different path, skip gracefully.
}

// TestDecoyDetector_RealAuditLine_DeniedRead loads a denied response audit line
// and confirms the detector does NOT fire on response entries.
func TestDecoyDetector_RealAuditLine_DeniedRead(t *testing.T) {
	ev := loadAuditFile(t, "denied-read-response.json")
	d := detect.NewDecoyDetector(decoys, kvMounts, evalPattern)
	findings := d.Inspect(ev)
	// Response entries must never fire.
	if len(findings) != 0 {
		t.Errorf("denied response: expected 0 findings, got %d (must not fire on responses)", len(findings))
	}
}
