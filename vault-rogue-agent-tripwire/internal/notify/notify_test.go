package notify

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/action"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/detect"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/event"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeFinding(sev detect.Severity, role, entityID, path string) detect.Finding {
	return detect.Finding{
		Severity: sev,
		Detector: "decoy",
		Reason:   "test reason",
		Event: event.Event{
			Type:       "request",
			RequestID:  "req-123",
			Path:       path,
			Operation:  "read",
			RemoteAddr: "10.0.0.1:12345",
			EntityID:   entityID,
			Metadata:   map[string]string{"role": role},
		},
	}
}

func makeKillResult(entityID, role string, degraded bool) action.KillResult {
	return action.KillResult{
		EntityID: entityID,
		Role:     role,
		Degraded: degraded,
		Steps: []action.StepStatus{
			{Name: "disable-entity", OK: true, Duration: 50 * time.Millisecond},
			{Name: "revoke-leases", OK: !degraded, Duration: 30 * time.Millisecond,
				Err: func() error {
						if degraded {
							return errors.New("POST sys/leases/revoke-prefix: HTTP 500")
						}
						return nil
					}(),
			},
			{Name: "verify-empty", OK: true, Duration: 20 * time.Millisecond},
		},
	}
}

// fakeWebhook starts an httptest server that records all POST bodies.
func fakeWebhook(t *testing.T) (url string, bodies func() []string) {
	t.Helper()
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Logf("webhook: read body: %v", err)
		}
		received = append(received, string(data))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string { return received }
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestFinding_NoWebhook(t *testing.T) {
	n := New("")
	// Should not panic; webhook goroutine must not be started.
	n.Finding(makeFinding(detect.SevKill, "eval-0412", "entity-abc", "kv/research/artifactory-admin"))
}

func TestFinding_WebhookPosted(t *testing.T) {
	url, bodies := fakeWebhook(t)
	n := New(url)
	f := makeFinding(detect.SevKill, "eval-0412", "entity-abc", "kv/research/artifactory-admin")
	n.Finding(f)

	// Give the async goroutine time to deliver.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(bodies()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("expected 1 webhook call, got %d", len(got))
	}

	// Payload must be valid JSON with a "text" key.
	var payload map[string]string
	if err := json.Unmarshal([]byte(got[0]), &payload); err != nil {
		t.Fatalf("webhook payload is not valid JSON: %v — body: %s", err, got[0])
	}
	text := payload["text"]
	if !strings.Contains(text, "KILL") {
		t.Errorf("expected KILL in text, got: %s", text)
	}
	if !strings.Contains(text, "eval-0412") {
		t.Errorf("expected role in text, got: %s", text)
	}
}

func TestFinding_PageSeverityInPayload(t *testing.T) {
	url, bodies := fakeWebhook(t)
	n := New(url)
	n.Finding(makeFinding(detect.SevPage, "", "", "kv/research/artifactory-admin"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(bodies()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("expected 1 webhook call, got %d", len(got))
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(got[0]), &payload); err != nil {
		t.Fatalf("webhook payload not valid JSON: %v", err)
	}
	if !strings.Contains(payload["text"], "PAGE") {
		t.Errorf("expected PAGE in text, got: %s", payload["text"])
	}
}

func TestKillResult_Completed(t *testing.T) {
	url, bodies := fakeWebhook(t)
	n := New(url)
	r := makeKillResult("entity-abc", "eval-0412", false)
	n.KillResult(r)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(bodies()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("expected 1 webhook call, got %d", len(got))
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(got[0]), &payload); err != nil {
		t.Fatalf("webhook payload not valid JSON: %v", err)
	}
	text := payload["text"]
	if !strings.Contains(text, "kill: completed") {
		t.Errorf("expected 'kill: completed' in text, got: %s", text)
	}
	if !strings.Contains(text, "entity-abc") {
		t.Errorf("expected entity_id in text, got: %s", text)
	}
}

func TestKillResult_Degraded(t *testing.T) {
	url, bodies := fakeWebhook(t)
	n := New(url)
	r := makeKillResult("entity-xyz", "eval-bad", true)
	n.KillResult(r)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(bodies()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("expected 1 webhook call, got %d", len(got))
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(got[0]), &payload); err != nil {
		t.Fatalf("webhook payload not valid JSON: %v", err)
	}
	text := payload["text"]
	if !strings.Contains(text, "KILL DEGRADED") {
		t.Errorf("expected 'KILL DEGRADED' in text, got: %s", text)
	}
}

func TestKillResult_NoWebhook(t *testing.T) {
	n := New("")
	// Should not panic.
	n.KillResult(makeKillResult("entity-abc", "eval-0412", false))
}

func TestWebhookFailure_NoPanic(t *testing.T) {
	// Point at a server that immediately closes — must not panic or block.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	srv.Close() // close immediately so the POST will fail

	n := New(srv.URL)
	// Give the goroutine time to fire and fail without crashing.
	n.Finding(makeFinding(detect.SevKill, "eval-0412", "entity-abc", "kv/x"))
	time.Sleep(100 * time.Millisecond)
}

func TestKillResultMessage_StepSummary(t *testing.T) {
	url, bodies := fakeWebhook(t)
	n := New(url)
	n.KillResult(makeKillResult("eid", "eval-0412", false))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(bodies()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := bodies()
	if len(got) == 0 {
		t.Fatal("no webhook calls received")
	}
	var payload map[string]string
	_ = json.Unmarshal([]byte(got[0]), &payload)
	// Steps should appear in text
	if !strings.Contains(payload["text"], "disable-entity") {
		t.Errorf("expected step names in text, got: %s", payload["text"])
	}
}
