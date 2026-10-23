// Package event parses raw Vault audit log lines into structured Event values.
//
// Vault writes one JSON object per line (newline-delimited). The JSON schema
// is defined in vault/audit/types.go (entry / request / response / auth).
package event

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Event is a parsed Vault audit log entry (request or response type).
type Event struct {
	Type       string            // "request" | "response"
	Time       time.Time
	RequestID  string
	Path       string
	Operation  string
	RemoteAddr string
	EntityID   string
	Accessor   string
	Metadata   map[string]string // auth.metadata values coerced to string
	Error      string            // top-level error field
}

// --- internal wire types (mirror vault/audit/types.go) ---------------------

type wireEntry struct {
	Type    string       `json:"type"`
	Time    string       `json:"time"`
	Error   string       `json:"error,omitempty"`
	Auth    *wireAuth    `json:"auth,omitempty"`
	Request *wireRequest `json:"request,omitempty"`
}

type wireRequest struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Operation  string `json:"operation"`
	RemoteAddr string `json:"remote_address"`
}

type wireAuth struct {
	EntityID string         `json:"entity_id"`
	Accessor string         `json:"accessor"`
	Metadata map[string]any `json:"metadata"`
}

// --------------------------------------------------------------------------

// Parse decodes a single newline-stripped audit log line into an Event.
// Returns an error if the line is not valid JSON or is missing required fields.
func Parse(line []byte) (Event, error) {
	var w wireEntry
	if err := json.Unmarshal(line, &w); err != nil {
		return Event{}, fmt.Errorf("json unmarshal: %w", err)
	}

	if w.Type == "" {
		return Event{}, fmt.Errorf("missing type field")
	}

	t, err := time.Parse(time.RFC3339Nano, w.Time)
	if err != nil {
		// Vault uses RFC3339Nano; fall back gracefully rather than dropping.
		t = time.Time{}
	}

	ev := Event{
		Type:  w.Type,
		Time:  t,
		Error: w.Error,
	}

	if w.Request != nil {
		ev.RequestID = w.Request.ID
		ev.Path = strings.TrimPrefix(w.Request.Path, "/")
		ev.Operation = w.Request.Operation
		ev.RemoteAddr = w.Request.RemoteAddr
	}

	if w.Auth != nil {
		ev.EntityID = w.Auth.EntityID
		ev.Accessor = w.Auth.Accessor
		ev.Metadata = coerceMetadata(w.Auth.Metadata)
	}

	return ev, nil
}

// coerceMetadata converts map[string]any → map[string]string by fmt.Sprint-ing
// each value. Vault stores metadata values as strings but the wire type is any.
func coerceMetadata(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch s := v.(type) {
		case string:
			out[k] = s
		default:
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

// kvSubpaths are the KV v2 API sub-paths that sit between the mount and the
// logical secret name. All of them must normalize to <mount>/<name>.
var kvSubpaths = []string{"data/", "metadata/", "delete/", "undelete/", "destroy/"}

// NormalizeKVPath maps a KV v2 internal API path back to its logical path.
//
// For each configured KV v2 mount, if path is:
//
//	<mount>/data/X, <mount>/metadata/X, <mount>/delete/X,
//	<mount>/undelete/X, <mount>/destroy/X
//
// it returns <mount>/X (the "logical" path without the operation sub-path).
// A leading slash is stripped first. Paths that do not match any KV v2 mount
// are returned unchanged (also with leading slash stripped).
//
// A list operation on a parent directory (e.g. kv/metadata/research/) is NOT
// normalized to a decoy path — the decoy detector must do an exact-match after
// normalization, so parent-list paths naturally won't match.
func NormalizeKVPath(path string, kvMounts []string) string {
	path = strings.TrimPrefix(path, "/")
	for _, mount := range kvMounts {
		prefix := mount + "/"
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := path[len(prefix):]
		for _, sub := range kvSubpaths {
			if strings.HasPrefix(rest, sub) {
				return mount + "/" + rest[len(sub):]
			}
		}
		// Path is under the mount but has no KV v2 sub-path — return as-is.
		return path
	}
	return path
}
