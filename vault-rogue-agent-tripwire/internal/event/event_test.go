package event_test

import (
	"testing"
	"time"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/event"
)

// These fixtures mirror real Vault audit lines (see vault/audit/types.go for the schema).
// Real captured lines will be added to testdata/audit/ after Task 2 lab verification.

var requestLine = []byte(`{
  "time": "2024-01-15T10:00:00.000000000Z",
  "type": "request",
  "auth": {
    "client_token": "hmac-sha256:abc",
    "accessor": "acc-cleartext-12345",
    "entity_id": "entity-uuid-abcd",
    "metadata": {
      "role": "eval-0412",
      "service_account_name": "eval-0412",
      "service_account_namespace": "evals"
    },
    "policies": ["eval-0412"],
    "token_type": "service"
  },
  "request": {
    "id": "req-uuid-1234",
    "operation": "read",
    "path": "kv/data/evals/0412/task",
    "remote_address": "192.168.49.2"
  }
}`)

var responseDeniedLine = []byte(`{
  "time": "2024-01-15T10:00:01.000000000Z",
  "type": "response",
  "error": "1 error occurred:\n\t* permission denied\n\n",
  "auth": {
    "accessor": "acc-cleartext-12345",
    "entity_id": "entity-uuid-abcd",
    "metadata": {
      "role": "eval-0412"
    },
    "token_type": "service"
  },
  "request": {
    "id": "req-uuid-5678",
    "operation": "read",
    "path": "kv/data/research/artifactory-admin",
    "remote_address": "192.168.49.2"
  }
}`)

func TestParse_Request(t *testing.T) {
	ev, err := event.Parse(requestLine)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if ev.Type != "request" {
		t.Errorf("Type = %q, want %q", ev.Type, "request")
	}
	want := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	if !ev.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", ev.Time, want)
	}
	if ev.RequestID != "req-uuid-1234" {
		t.Errorf("RequestID = %q, want %q", ev.RequestID, "req-uuid-1234")
	}
	if ev.Path != "kv/data/evals/0412/task" {
		t.Errorf("Path = %q, want %q", ev.Path, "kv/data/evals/0412/task")
	}
	if ev.Operation != "read" {
		t.Errorf("Operation = %q, want %q", ev.Operation, "read")
	}
	if ev.RemoteAddr != "192.168.49.2" {
		t.Errorf("RemoteAddr = %q, want %q", ev.RemoteAddr, "192.168.49.2")
	}
	if ev.EntityID != "entity-uuid-abcd" {
		t.Errorf("EntityID = %q, want %q", ev.EntityID, "entity-uuid-abcd")
	}
	if ev.Accessor != "acc-cleartext-12345" {
		t.Errorf("Accessor = %q, want %q", ev.Accessor, "acc-cleartext-12345")
	}
	if ev.Metadata["role"] != "eval-0412" {
		t.Errorf("Metadata[role] = %q, want %q", ev.Metadata["role"], "eval-0412")
	}
	if ev.Metadata["service_account_name"] != "eval-0412" {
		t.Errorf("Metadata[service_account_name] = %q, want %q", ev.Metadata["service_account_name"], "eval-0412")
	}
	if ev.Metadata["service_account_namespace"] != "evals" {
		t.Errorf("Metadata[service_account_namespace] = %q, want %q", ev.Metadata["service_account_namespace"], "evals")
	}
	if ev.Error != "" {
		t.Errorf("Error = %q, want empty", ev.Error)
	}
}

func TestParse_ResponseDenied(t *testing.T) {
	ev, err := event.Parse(responseDeniedLine)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if ev.Type != "response" {
		t.Errorf("Type = %q, want %q", ev.Type, "response")
	}
	if ev.Error == "" {
		t.Error("Error should be non-empty for a denied response")
	}
	if ev.Path != "kv/data/research/artifactory-admin" {
		t.Errorf("Path = %q, want %q", ev.Path, "kv/data/research/artifactory-admin")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := event.Parse([]byte(`{not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParse_MissingType(t *testing.T) {
	_, err := event.Parse([]byte(`{"time":"2024-01-15T10:00:00Z","request":{"id":"x"}}`))
	if err == nil {
		t.Error("expected error for missing type, got nil")
	}
}

func TestParse_LeadingSlashStripped(t *testing.T) {
	line := []byte(`{
		"type": "request",
		"time": "2024-01-15T10:00:00Z",
		"request": {"id": "x", "operation": "read", "path": "/kv/data/foo", "remote_address": "1.2.3.4"}
	}`)
	ev, err := event.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Path != "kv/data/foo" {
		t.Errorf("Path = %q, want leading slash stripped", ev.Path)
	}
}

func TestParse_NoAuth(t *testing.T) {
	line := []byte(`{
		"type": "request",
		"time": "2024-01-15T10:00:00Z",
		"request": {"id": "x", "operation": "read", "path": "sys/health", "remote_address": "127.0.0.1"}
	}`)
	ev, err := event.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.EntityID != "" {
		t.Errorf("EntityID = %q, want empty", ev.EntityID)
	}
	if ev.Metadata != nil {
		t.Errorf("Metadata = %v, want nil", ev.Metadata)
	}
}
