// Package detect defines the detector interface and decoy detector for
// identifying rogue agent behavior in the Vault audit stream.
package detect

import (
	"regexp"
	"sync"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/event"
)

// Severity classifies the urgency of a finding.
type Severity int

const (
	SevInfo Severity = iota // informational only
	SevPage                 // alert but do not kill
	SevKill                 // kill the offending identity
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevPage:
		return "PAGE"
	case SevKill:
		return "KILL"
	default:
		return "UNKNOWN"
	}
}

// Finding is produced by a Detector when it identifies a notable event.
type Finding struct {
	Severity Severity
	Detector string
	Reason   string
	Event    event.Event
}

// Detector inspects a single event and returns zero or more findings.
type Detector interface {
	Name() string
	Inspect(e event.Event) []Finding
}

// DecoyDetector fires when a request event touches one of the configured
// decoy paths (after KV v2 path normalization).
//
// Severity rules:
//   - SevKill if auth.metadata["role"] matches eval_role_pattern AND entity_id is non-empty.
//   - SevPage otherwise (admin token, unknown identity, etc.)
//
// Deduplication: each RequestID is processed at most once.
type DecoyDetector struct {
	decoys          map[string]struct{} // logical paths (pre-normalized)
	kvMounts        []string
	evalRolePattern *regexp.Regexp

	mu   sync.Mutex
	seen map[string]struct{} // request IDs already actioned
}

// NewDecoyDetector creates a DecoyDetector.
// decoys must be logical KV paths without a data/metadata prefix
// (e.g. "kv/research/artifactory-admin").
func NewDecoyDetector(decoys []string, kvMounts []string, evalRolePattern *regexp.Regexp) *DecoyDetector {
	d := &DecoyDetector{
		decoys:          make(map[string]struct{}, len(decoys)),
		kvMounts:        kvMounts,
		evalRolePattern: evalRolePattern,
		seen:            make(map[string]struct{}),
	}
	for _, p := range decoys {
		d.decoys[p] = struct{}{}
	}
	return d
}

// Name returns the detector's identifier.
func (d *DecoyDetector) Name() string { return "decoy" }

// Inspect checks whether the event is a request for a decoy path.
func (d *DecoyDetector) Inspect(e event.Event) []Finding {
	// Only act on request entries — response entries for the same request are
	// deduplicated by RequestID and carry no new information for detection.
	if e.Type != "request" {
		return nil
	}

	// Normalize the path and check against configured decoys.
	normalized := event.NormalizeKVPath(e.Path, d.kvMounts)
	if _, isDecoy := d.decoys[normalized]; !isDecoy {
		return nil
	}

	// Deduplicate by RequestID.
	if e.RequestID != "" {
		d.mu.Lock()
		_, already := d.seen[e.RequestID]
		if !already {
			d.seen[e.RequestID] = struct{}{}
		}
		d.mu.Unlock()
		if already {
			return nil
		}
	}

	sev, reason := d.severity(e)
	return []Finding{{
		Severity: sev,
		Detector: d.Name(),
		Reason:   reason,
		Event:    e,
	}}
}

// severity determines whether this decoy touch warrants a kill or just a page.
func (d *DecoyDetector) severity(e event.Event) (Severity, string) {
	role := e.Metadata["role"]
	isEvalRole := role != "" && d.evalRolePattern.MatchString(role)
	hasEntity := e.EntityID != ""

	if isEvalRole && hasEntity {
		return SevKill, "eval identity read decoy path"
	}

	if role != "" {
		return SevPage, "non-eval identity read decoy path (role=" + role + ")"
	}
	return SevPage, "unidentified identity read decoy path"
}
