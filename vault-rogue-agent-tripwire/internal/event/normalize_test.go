package event_test

import (
	"testing"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/event"
)

func TestNormalizeKVPath(t *testing.T) {
	mounts := []string{"kv", "secret"}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// ── KV v2 sub-path variants ───────────────────────────────────────────
		{
			name:  "data sub-path",
			input: "kv/data/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		{
			name:  "metadata sub-path",
			input: "kv/metadata/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		{
			name:  "delete sub-path",
			input: "kv/delete/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		{
			name:  "undelete sub-path",
			input: "kv/undelete/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		{
			name:  "destroy sub-path",
			input: "kv/destroy/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		// ── leading slash stripped ───────────────────────────────────────────
		{
			name:  "leading slash stripped before normalization",
			input: "/kv/data/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		// ── second mount ─────────────────────────────────────────────────────
		{
			name:  "second KV mount normalized",
			input: "secret/data/foo/bar",
			want:  "secret/foo/bar",
		},
		// ── parent list — must NOT normalize to decoy ─────────────────────────
		{
			name:  "list on parent directory is not a match (metadata sub-path directory)",
			input: "kv/metadata/research/",
			want:  "kv/research/",
		},
		// ── non-KV path unchanged ─────────────────────────────────────────────
		{
			name:  "non-KV path unchanged",
			input: "database/creds/eval-0412",
			want:  "database/creds/eval-0412",
		},
		{
			name:  "sys path unchanged",
			input: "sys/health",
			want:  "sys/health",
		},
		// ── path under KV mount but no sub-path ──────────────────────────────
		{
			name:  "path under KV mount but no KV v2 sub-path prefix",
			input: "kv/research/artifactory-admin",
			want:  "kv/research/artifactory-admin",
		},
		// ── deep path ─────────────────────────────────────────────────────────
		{
			name:  "deep nested path under data",
			input: "kv/data/a/b/c/d",
			want:  "kv/a/b/c/d",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := event.NormalizeKVPath(tc.input, mounts)
			if got != tc.want {
				t.Errorf("NormalizeKVPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
