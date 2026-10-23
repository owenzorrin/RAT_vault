// Package action implements the kill action: disable a Vault entity and revoke
// all dynamic leases belonging to the associated eval run.
package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"
)

// StepStatus tracks the outcome of a single kill step.
type StepStatus struct {
	Name     string
	OK       bool
	Duration time.Duration
	Err      error
}

// KillResult is returned by Killer.Kill and summarises the full kill attempt.
type KillResult struct {
	EntityID string
	Role     string
	Degraded bool // true if any step failed after exhausting retries
	Steps    []StepStatus
}

// VaultClient is the minimal interface for Vault API calls used by Killer.
// Implemented by *http.Client wrapper; mocked in tests.
type VaultClient interface {
	// Write performs a PUT/POST to path with the JSON body.
	Write(ctx context.Context, path string, body map[string]any) error
	// List performs a LIST on path; returns the keys slice or nil if empty/404.
	List(ctx context.Context, path string) ([]string, error)
}

// Killer executes the kill sequence for a rogue eval identity.
type Killer struct {
	client              VaultClient
	leasePrefixTemplate *template.Template
	dryRun              bool

	mu      sync.Mutex
	killed  map[string]struct{} // entity IDs killed in this process lifetime
}

// NewKiller creates a Killer.
func NewKiller(client VaultClient, leasePrefixTmpl string, dryRun bool) (*Killer, error) {
	tmpl, err := template.New("lease").Parse(leasePrefixTmpl)
	if err != nil {
		return nil, fmt.Errorf("invalid lease_prefix_template: %w", err)
	}
	return &Killer{
		client:              client,
		leasePrefixTemplate: tmpl,
		dryRun:              dryRun,
		killed:              make(map[string]struct{}),
	}, nil
}

// Kill disables the entity and revokes all leases for the given role.
// It is safe to call concurrently. Each Vault call is retried up to 3 times
// with exponential backoff (~200 ms base). A failed step marks the result
// Degraded but does not abort subsequent steps.
func (k *Killer) Kill(ctx context.Context, entityID, role string) KillResult {
	result := KillResult{EntityID: entityID, Role: role}

	if k.dryRun {
		leasePrefix := k.renderLeasePrefix(role)
		slog.Info("kill: dry-run — would execute",
			"entity_id", entityID,
			"step1", fmt.Sprintf("POST identity/entity/id/%s {disabled:true}", entityID),
			"step2", fmt.Sprintf("PUT sys/leases/revoke-prefix/%s", leasePrefix),
			"step3", fmt.Sprintf("LIST sys/leases/lookup/%s", leasePrefix),
		)
		return result
	}

	// Idempotency: skip if already killed in this process lifetime.
	k.mu.Lock()
	_, already := k.killed[entityID]
	if !already {
		k.killed[entityID] = struct{}{}
	}
	k.mu.Unlock()
	if already {
		slog.Info("kill: entity already killed in this session, skipping", "entity_id", entityID)
		return result
	}

	leasePrefix := k.renderLeasePrefix(role)

	// Step 1: disable entity (do this first — blocks new token use immediately,
	// closing the window between revoke and a racing mint).
	result.Steps = append(result.Steps, k.step(ctx, "disable-entity", func() error {
		return retry(ctx, 3, 200*time.Millisecond, func() error {
			return k.client.Write(ctx, "identity/entity/id/"+entityID,
				map[string]any{"disabled": true})
		})
	}))

	// Step 2: revoke all leases under the role's DB credential prefix.
	result.Steps = append(result.Steps, k.step(ctx, "revoke-leases", func() error {
		return retry(ctx, 3, 200*time.Millisecond, func() error {
			return k.client.Write(ctx, "sys/leases/revoke-prefix/"+leasePrefix, nil)
		})
	}))

	// Step 3: verify — list the prefix; expect empty or 404.
	result.Steps = append(result.Steps, k.step(ctx, "verify-empty", func() error {
		keys, err := k.client.List(ctx, "sys/leases/lookup/"+leasePrefix)
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			return fmt.Errorf("leases still present after revocation: %v", keys)
		}
		return nil
	}))

	for _, s := range result.Steps {
		if !s.OK {
			result.Degraded = true
			break
		}
	}

	return result
}

// step times and executes fn, returning a StepStatus.
func (k *Killer) step(ctx context.Context, name string, fn func() error) StepStatus {
	start := time.Now()
	err := fn()
	s := StepStatus{Name: name, Duration: time.Since(start), OK: err == nil, Err: err}
	if err != nil {
		slog.Error("kill: step failed", "step", name, "err", err, "duration", s.Duration)
	} else {
		slog.Info("kill: step ok", "step", name, "duration", s.Duration)
	}
	return s
}

// renderLeasePrefix executes the template with Role set.
func (k *Killer) renderLeasePrefix(role string) string {
	var buf bytes.Buffer
	_ = k.leasePrefixTemplate.Execute(&buf, struct{ Role string }{role})
	return buf.String()
}

// retry calls fn up to maxAttempts times, backing off exponentially from base.
// Returns the last error if all attempts fail.
func retry(ctx context.Context, maxAttempts int, base time.Duration, fn func() error) error {
	var err error
	for i := 0; i < maxAttempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i == maxAttempts-1 {
			break
		}
		wait := time.Duration(math.Pow(2, float64(i))) * base
		slog.Warn("kill: retrying after error", "attempt", i+1, "wait", wait, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return fmt.Errorf("after %d attempts: %w", maxAttempts, err)
}

// ── HTTP VaultClient implementation ──────────────────────────────────────────

// HTTPVaultClient implements VaultClient against a real Vault instance.
type HTTPVaultClient struct {
	addr  string // e.g. "http://127.0.0.1:8200"
	token string
	http  *http.Client
}

// NewHTTPVaultClient creates a client using the given Vault address and token.
func NewHTTPVaultClient(addr, token string) *HTTPVaultClient {
	return &HTTPVaultClient{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Write performs a PUT to path with the optional JSON body.
func (c *HTTPVaultClient) Write(ctx context.Context, path string, body map[string]any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = bytes.NewReader([]byte("{}"))
	}

	url := c.addr + "/v1/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: HTTP %d: %s", path, resp.StatusCode, string(respBody))
	}
	return nil
}

// List performs a LIST request on path. Returns nil slice on 404 (no leases).
func (c *HTTPVaultClient) List(ctx context.Context, path string) ([]string, error) {
	url := c.addr + "/v1/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequestWithContext(ctx, "LIST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LIST %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no leases — treat as empty
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("LIST %s: HTTP %d: %s", path, resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("LIST %s: unmarshal: %w", path, err)
	}
	return result.Data.Keys, nil
}
