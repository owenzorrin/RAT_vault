// Package ingest provides a TCP listener that reads newline-delimited audit
// log entries from a Vault socket audit device and forwards them onto a
// buffered channel for downstream processing.
package ingest

import (
	"bufio"
	"log/slog"
	"net"
	"sync/atomic"
)

const (
	// maxTokenBytes is the maximum size of a single audit line.
	// Vault audit lines can be large when request/response data is included.
	maxTokenBytes = 1 << 20 // 1 MiB
)

// Listener accepts TCP connections from Vault's socket audit device and
// pushes raw audit lines onto Lines.
type Listener struct {
	Lines    chan []byte
	drops    atomic.Int64
	bufSize  int
}

// New creates a Listener with the given channel buffer size.
func New(bufSize int) *Listener {
	return &Listener{
		Lines:   make(chan []byte, bufSize),
		bufSize: bufSize,
	}
}

// Drops returns the total number of lines dropped due to a full channel.
func (l *Listener) Drops() int64 {
	return l.drops.Load()
}

// ListenAndServe binds to addr and accepts connections until ctx is cancelled.
// Each accepted connection is handled in its own goroutine.
func (l *Listener) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("ingest: listening", "addr", ln.Addr())

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Listener was closed — normal shutdown path.
				slog.Debug("ingest: accept error (listener closed?)", "err", err)
				return
			}
			slog.Debug("ingest: new connection", "remote", conn.RemoteAddr())
			go l.readConn(conn)
		}
	}()

	return nil
}

// readConn reads newline-delimited JSON lines from a single connection until
// it is closed by Vault. Lines too large for the scanner token buffer are
// logged and skipped — they will not be lost from Vault's file device.
func (l *Listener) readConn(conn net.Conn) {
	defer func() {
		conn.Close()
		slog.Debug("ingest: connection closed", "remote", conn.RemoteAddr())
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxTokenBytes), maxTokenBytes)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Copy the slice — scanner reuses its buffer.
		buf := make([]byte, len(line))
		copy(buf, line)

		select {
		case l.Lines <- buf:
		default:
			l.drops.Add(1)
			slog.Warn("ingest: channel full, dropping line",
				"drops_total", l.drops.Load(),
				"line_prefix", string(buf[:min(64, len(buf))]),
			)
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Warn("ingest: scanner error", "remote", conn.RemoteAddr(), "err", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
