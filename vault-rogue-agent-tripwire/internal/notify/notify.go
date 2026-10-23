// Package notify emits structured findings and kill results to stdout (JSON)
// and optionally POSTs a Slack-compatible payload to a webhook URL.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/action"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/detect"
)

// Notifier emits findings and kill results.
type Notifier struct {
	webhookURL string
	http       *http.Client
}

// New creates a Notifier. webhookURL may be empty (webhook disabled).
func New(webhookURL string) *Notifier {
	return &Notifier{
		webhookURL: webhookURL,
		http:       &http.Client{Timeout: 5 * time.Second},
	}
}

// ── Finding notification ──────────────────────────────────────────────────────

// FindingMessage is the JSON shape emitted to stdout for a finding.
type FindingMessage struct {
	Timestamp  string            `json:"timestamp"`
	MsgType    string            `json:"msg_type"` // "finding"
	Severity   string            `json:"severity"`
	Detector   string            `json:"detector"`
	Reason     string            `json:"reason"`
	RequestID  string            `json:"request_id"`
	Path       string            `json:"path"`
	EntityID   string            `json:"entity_id"`
	Role       string            `json:"role,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Finding logs a detect.Finding as structured JSON to stdout and, if a webhook
// is configured, POSTs a Slack-compatible payload asynchronously.
func (n *Notifier) Finding(f detect.Finding) {
	msg := FindingMessage{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		MsgType:    "finding",
		Severity:   f.Severity.String(),
		Detector:   f.Detector,
		Reason:     f.Reason,
		RequestID:  f.Event.RequestID,
		Path:       f.Event.Path,
		EntityID:   f.Event.EntityID,
		Role:       f.Event.Metadata["role"],
		RemoteAddr: f.Event.RemoteAddr,
		Metadata:   f.Event.Metadata,
	}

	slog.Info("notify: finding", slogAttrs(msg)...)

	if n.webhookURL != "" {
		go n.postSlack(n.findingSlackPayload(msg))
	}
}

func (n *Notifier) findingSlackPayload(msg FindingMessage) string {
	text := fmt.Sprintf("[%s] %s detector=%s path=%s entity=%s role=%s reason=%q",
		msg.Severity, msg.MsgType, msg.Detector, msg.Path,
		msg.EntityID, msg.Role, msg.Reason)
	return slackText(text)
}

// ── Kill result notification ──────────────────────────────────────────────────

// KillResultMessage is the JSON shape emitted to stdout for a kill result.
type KillResultMessage struct {
	Timestamp string        `json:"timestamp"`
	MsgType   string        `json:"msg_type"` // "kill_result"
	EntityID  string        `json:"entity_id"`
	Role      string        `json:"role"`
	Degraded  bool          `json:"degraded"`
	Steps     []StepMessage `json:"steps"`
}

// StepMessage is the per-step summary inside KillResultMessage.
type StepMessage struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Duration string `json:"duration"`
	Err      string `json:"err,omitempty"`
}

// KillResult logs an action.KillResult as structured JSON to stdout and, if a
// webhook is configured, POSTs a Slack-compatible payload asynchronously.
func (n *Notifier) KillResult(r action.KillResult) {
	steps := make([]StepMessage, len(r.Steps))
	for i, s := range r.Steps {
		sm := StepMessage{
			Name:     s.Name,
			OK:       s.OK,
			Duration: s.Duration.String(),
		}
		if s.Err != nil {
			sm.Err = s.Err.Error()
		}
		steps[i] = sm
	}

	msg := KillResultMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		MsgType:   "kill_result",
		EntityID:  r.EntityID,
		Role:      r.Role,
		Degraded:  r.Degraded,
		Steps:     steps,
	}

	level := slog.LevelInfo
	logMsg := "kill: completed"
	if r.Degraded {
		level = slog.LevelError
		logMsg = "KILL DEGRADED"
	}
	slog.Log(context.Background(), level, logMsg, slogKillAttrs(msg)...)

	if n.webhookURL != "" {
		go n.postSlack(n.killSlackPayload(msg))
	}
}

func (n *Notifier) killSlackPayload(msg KillResultMessage) string {
	prefix := "kill: completed"
	if msg.Degraded {
		prefix = "KILL DEGRADED"
	}
	var stepSummary strings.Builder
	for _, s := range msg.Steps {
		status := "ok"
		if !s.OK {
			status = fmt.Sprintf("FAILED(%s)", s.Err)
		}
		fmt.Fprintf(&stepSummary, " %s=%s(%s)", s.Name, status, s.Duration)
	}
	text := fmt.Sprintf("[%s] entity=%s role=%s%s", prefix, msg.EntityID, msg.Role, stepSummary.String())
	return slackText(text)
}

// ── Webhook helper ────────────────────────────────────────────────────────────

func (n *Notifier) postSlack(payload string) {
	resp, err := n.http.Post(n.webhookURL, "application/json", strings.NewReader(payload)) //nolint:noctx
	if err != nil {
		slog.Warn("notify: webhook POST failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("notify: webhook POST non-2xx", "status", resp.StatusCode)
	}
}

// slackText wraps plain text in the minimal Slack incoming-webhook JSON format.
func slackText(text string) string {
	b, _ := json.Marshal(map[string]string{"text": text})
	return string(b)
}

// ── slog attribute helpers ────────────────────────────────────────────────────

func slogAttrs(m FindingMessage) []any {
	return []any{
		"msg_type", m.MsgType,
		"severity", m.Severity,
		"detector", m.Detector,
		"reason", m.Reason,
		"request_id", m.RequestID,
		"path", m.Path,
		"entity_id", m.EntityID,
		"role", m.Role,
		"remote_addr", m.RemoteAddr,
	}
}

func slogKillAttrs(m KillResultMessage) []any {
	attrs := []any{
		"msg_type", m.MsgType,
		"entity_id", m.EntityID,
		"role", m.Role,
		"degraded", m.Degraded,
	}
	for _, s := range m.Steps {
		if s.OK {
			attrs = append(attrs, s.Name, fmt.Sprintf("ok(%s)", s.Duration))
		} else {
			attrs = append(attrs, s.Name, fmt.Sprintf("FAILED(%s):%s", s.Duration, s.Err))
		}
	}
	return attrs
}

