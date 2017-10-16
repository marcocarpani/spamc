// Package fakeconn provides a "fake" net.Conn implementation for tests.
package fakeconn

import (
	"bytes"
	"net"
	"time"
)

var _ net.Conn = Conn{}

// Conn is a fake net.Conn implementations. Everything that is written to it
// with Write is available in the Written parameter.
//
// The Read() function will read from the data set in ReadFrom.
type Conn struct {
	Written  *bytes.Buffer
	ReadFrom *bytes.Buffer
}

// New instance factory.
func New() Conn {
	return Conn{
		Written:  bytes.NewBuffer([]byte{}),
		ReadFrom: bytes.NewBuffer([]byte{}),
	}
}

func (c Conn) Write(b []byte) (n int, err error) {
	c.Written.Write(b)
	return len(b), nil
}

func (c Conn) Read(b []byte) (n int, err error) {
	return c.ReadFrom.Read(b)
}

// Close does nothing.
func (c Conn) Close() error { return nil }

// LocalAddr does nothing.
func (c Conn) LocalAddr() net.Addr { return &net.TCPAddr{} }

// RemoteAddr does nothing.
func (c Conn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

// SetDeadline does nothing.
func (c Conn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline does nothing.
func (c Conn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline does nothing.
func (c Conn) SetWriteDeadline(t time.Time) error { return nil }
