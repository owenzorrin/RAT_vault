package action_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/action"
)

// ── fake VaultClient ─────────────────────────────────────────────────────────

type call struct {
	method string
	path   string
}

type fakeClient struct {
	calls      []call
	writeErr   error // returned on every Write
	listKeys   []string
	listErr    error
	writeCount atomic.Int32
	// failFirstN: return writeErr for first N Write calls, then succeed
	failFirstN int
}

func (f *fakeClient) Write(_ context.Context, path string, _ map[string]any) error {
	f.calls = append(f.calls, call{"write", path})
	n := int(f.writeCount.Add(1))
	if f.failFirstN > 0 && n <= f.failFirstN {
		return f.writeErr
	}
	if f.failFirstN == 0 && f.writeErr != nil {
		return f.writeErr
	}
	return nil
}

func (f *fakeClient) List(_ context.Context, path string) ([]string, error) {
	f.calls = append(f.calls, call{"list", path})
	return f.listKeys, f.listErr
}

func newKiller(t *testing.T, client action.VaultClient, dryRun bool) *action.Killer {
	t.Helper()
	k, err := action.NewKiller(client, "database/creds/{{.Role}}", dryRun)
	if err != nil {
		t.Fatalf("NewKiller: %v", err)
	}
	return k
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestKill_CallOrder(t *testing.T) {
	c := &fakeClient{}
	k := newKiller(t, c, false)

	result := k.Kill(context.Background(), "entity-1", "eval-0412")

	if result.Degraded {
		t.Errorf("unexpected degraded result: %+v", result.Steps)
	}
	// Expect exactly: write(identity), write(revoke-prefix), list(lookup)
	if len(c.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d: %v", len(c.calls), c.calls)
	}
	if !strings.Contains(c.calls[0].path, "identity/entity/id/entity-1") {
		t.Errorf("step 1 wrong path: %s", c.calls[0].path)
	}
	if !strings.Contains(c.calls[1].path, "sys/leases/revoke-prefix/database/creds/eval-0412") {
		t.Errorf("step 2 wrong path: %s", c.calls[1].path)
	}
	if !strings.Contains(c.calls[2].path, "sys/leases/lookup/database/creds/eval-0412") {
		t.Errorf("step 3 wrong path: %s", c.calls[2].path)
	}
}

func TestKill_DryRunMakesZeroCalls(t *testing.T) {
	c := &fakeClient{}
	k := newKiller(t, c, true)

	result := k.Kill(context.Background(), "entity-1", "eval-0412")

	if len(c.calls) != 0 {
		t.Errorf("dry-run made %d calls, expected 0: %v", len(c.calls), c.calls)
	}
	if result.Degraded {
		t.Error("dry-run should not set Degraded")
	}
}

func TestKill_Idempotency(t *testing.T) {
	c := &fakeClient{}
	k := newKiller(t, c, false)

	k.Kill(context.Background(), "entity-1", "eval-0412")
	callsAfterFirst := len(c.calls)

	k.Kill(context.Background(), "entity-1", "eval-0412") // same entity ID
	if len(c.calls) != callsAfterFirst {
		t.Errorf("second kill made new calls: %v (expected idempotent)", c.calls[callsAfterFirst:])
	}
}

func TestKill_DifferentEntitiesNotDeduplicated(t *testing.T) {
	c := &fakeClient{}
	k := newKiller(t, c, false)

	k.Kill(context.Background(), "entity-1", "eval-0412")
	k.Kill(context.Background(), "entity-2", "eval-0413")

	if len(c.calls) != 6 { // 3 steps × 2 entities
		t.Errorf("expected 6 calls for 2 entities, got %d", len(c.calls))
	}
}

func TestKill_RetryThenSuccess(t *testing.T) {
	c := &fakeClient{
		writeErr:   fmt.Errorf("transient"),
		failFirstN: 1, // fail only the very first Write call
	}
	k := newKiller(t, c, false)

	result := k.Kill(context.Background(), "entity-1", "eval-0412")

	if result.Degraded {
		t.Errorf("expected success after retry, got degraded: %+v", result.Steps)
	}
	// First Write is retried (2 calls to Write for step 1) + step 2 + step 3 list
	writeCallCount := 0
	for _, c := range c.calls {
		if c.method == "write" {
			writeCallCount++
		}
	}
	if writeCallCount < 3 { // at minimum: retry(entity) + revoke + no list retry
		t.Errorf("expected >=3 write calls (retry path), got %d", writeCallCount)
	}
}

func TestKill_RetryExhausted_Degraded(t *testing.T) {
	c := &fakeClient{
		writeErr: fmt.Errorf("permanent error"),
	}
	k := newKiller(t, c, false)

	result := k.Kill(context.Background(), "entity-1", "eval-0412")

	if !result.Degraded {
		t.Error("expected Degraded when all retries fail")
	}
	// Step 1 should have failed
	if len(result.Steps) == 0 || result.Steps[0].OK {
		t.Errorf("step 1 should have failed: %+v", result.Steps)
	}
}

func TestKill_VerifyStep_LeasesRemain_Degraded(t *testing.T) {
	c := &fakeClient{
		listKeys: []string{"database/creds/eval-0412/abc123"},
	}
	k := newKiller(t, c, false)

	result := k.Kill(context.Background(), "entity-1", "eval-0412")

	if !result.Degraded {
		t.Error("expected Degraded when leases remain after revocation")
	}
	// Find the verify step
	var verifyStep *action.StepStatus
	for i := range result.Steps {
		if result.Steps[i].Name == "verify-empty" {
			verifyStep = &result.Steps[i]
		}
	}
	if verifyStep == nil || verifyStep.OK {
		t.Errorf("verify-empty step should have failed: %+v", result.Steps)
	}
}

func TestKill_VerifyStep_404_OK(t *testing.T) {
	// nil keys (404 from Vault) means no leases — should succeed
	c := &fakeClient{listKeys: nil}
	k := newKiller(t, c, false)

	result := k.Kill(context.Background(), "entity-1", "eval-0412")

	if result.Degraded {
		t.Errorf("nil list keys (404) should be OK, got degraded: %+v", result.Steps)
	}
}

// ── HTTPVaultClient integration test against a fake HTTP server ─────────────

func TestHTTPVaultClient_Write(t *testing.T) {
	var gotMethod, gotPath, gotToken string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Vault-Token")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := action.NewHTTPVaultClient(srv.URL, "test-token")
	err := c.Write(context.Background(), "identity/entity/id/abc", map[string]any{"disabled": true})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/v1/identity/entity/id/abc" {
		t.Errorf("path = %s, want /v1/identity/entity/id/abc", gotPath)
	}
	if gotToken != "test-token" {
		t.Errorf("token = %s, want test-token", gotToken)
	}
	if gotBody["disabled"] != true {
		t.Errorf("body[disabled] = %v, want true", gotBody["disabled"])
	}
}

func TestHTTPVaultClient_List_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := action.NewHTTPVaultClient(srv.URL, "test-token")
	keys, err := c.List(context.Background(), "sys/leases/lookup/database/creds/eval-0412")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys on 404, got %v", keys)
	}
}

func TestHTTPVaultClient_List_WithKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"abc123", "def456"},
			},
		})
	}))
	defer srv.Close()

	c := action.NewHTTPVaultClient(srv.URL, "test-token")
	keys, err := c.List(context.Background(), "sys/leases/lookup/database/creds/eval-0412")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %v", keys)
	}
}

func TestKill_ContextCancelled_DuringRetry(t *testing.T) {
	c := &fakeClient{writeErr: fmt.Errorf("error")}
	k := newKiller(t, c, false)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	result := k.Kill(ctx, "entity-1", "eval-0412")
	elapsed := time.Since(start)

	// Should abort well before 3×200ms backoff (600ms)
	if elapsed > 400*time.Millisecond {
		t.Errorf("context cancel not respected: elapsed %v", elapsed)
	}
	if !result.Degraded {
		t.Error("expected Degraded when context cancelled")
	}
}
