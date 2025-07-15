package server

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
)

// PeekConn is a buffered Conn for peeking into the connection.
type PeekConn struct {
	net.Conn
	r *bufio.Reader
}

// Read reads data from the connection using the buffered reader.
// This ensures that any data previously peeked is properly read from the buffer.
func (c *PeekConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// Peek returns the next n bytes without advancing the reader.
// The bytes stop being valid at the next read call.
func (c *PeekConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func newPeekConn(c net.Conn) *PeekConn {
	return &PeekConn{c, bufio.NewReader(c)}
}

// HybridListener inspects the first bytes of the connection to determine
// whether to serve unencrypted HTTP or TLS. This allows using the same TCP port
// for both, which is convenient for reducing the configuration burden on the user.
// Source: https://github.com/foreverzmy/http-s-listen-same-port/
type HybridListener struct {
	net.Listener
	tlsConfig *tls.Config
	logger    *slog.Logger
}

// Accept waits for and returns the next connection to the listener.
// It inspects the first few bytes of the connection to determine if it's a TLS
// handshake and returns either a TLS-wrapped connection or a plain HTTP
// connection accordingly.
func (ln *HybridListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	peekConn := newPeekConn(conn)

	b, err := peekConn.Peek(3)
	if err != nil {
		peekConn.Close()
		if err != io.EOF {
			return nil, err
		}
	}

	if b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x03 {
		ln.logger.Debug("accepting TLS connection")
		return tls.Server(peekConn, ln.tlsConfig), nil
	}

	ln.logger.Debug("accepting HTTP connection")
	return peekConn, nil
}
