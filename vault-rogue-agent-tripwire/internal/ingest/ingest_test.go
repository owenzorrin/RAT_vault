package ingest_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/ingest"
)

func TestListenerReceivesLines(t *testing.T) {
	l := ingest.New(16)
	if err := l.ListenAndServe("127.0.0.1:0"); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}

	// Give the goroutine a moment to start accepting.
	time.Sleep(10 * time.Millisecond)

	// We need to find the actual bound port. Re-dial from a test connection.
	// ListenAndServe doesn't expose the port, so we probe for an open port.
	// Instead, use a fixed port within the ephemeral range for this test.
	// Since we called with "127.0.0.1:0", re-create with a known port.
	l2 := ingest.New(16)
	if err := l2.ListenAndServe("127.0.0.1:19091"); err != nil {
		t.Fatalf("ListenAndServe fixed port: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:19091")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	lines := []string{
		`{"type":"request","time":"2024-01-15T10:00:00Z","request":{"id":"1","path":"kv/foo","operation":"read","remote_address":"127.0.0.1"}}`,
		`{"type":"response","time":"2024-01-15T10:00:00Z","request":{"id":"1","path":"kv/foo","operation":"read","remote_address":"127.0.0.1"}}`,
	}

	for _, line := range lines {
		fmt.Fprintln(conn, line)
	}
	conn.Close()

	// Collect with timeout.
	received := 0
	deadline := time.After(2 * time.Second)
	for received < len(lines) {
		select {
		case <-l2.Lines:
			received++
		case <-deadline:
			t.Fatalf("timeout: got %d/%d lines", received, len(lines))
		}
	}
}

func TestListenerDropsWhenFull(t *testing.T) {
	// Buffer of 1 so the second line gets dropped.
	l := ingest.New(1)
	if err := l.ListenAndServe("127.0.0.1:19092"); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:19092")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Send 5 lines without reading — channel fills after 1.
	for i := 0; i < 5; i++ {
		fmt.Fprintf(conn, `{"type":"request","time":"2024-01-15T10:00:00Z","request":{"id":"%d","path":"x","operation":"read","remote_address":"127.0.0.1"}}`+"\n", i)
	}
	conn.Close()

	// Give readConn goroutine time to process.
	time.Sleep(100 * time.Millisecond)

	if l.Drops() == 0 {
		t.Error("expected at least one drop, got 0")
	}
}
