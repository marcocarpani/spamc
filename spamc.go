package spamc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

const clientProtocolVersion = "1.5"

var serverProtocolVersions = []string{"1.0", "1.1"}

// mapping of the error codes to the error messages.
var errorMessages = map[int]string{
	64: "Command line usage error",               // EX_USAGE
	65: "Data format error",                      // EX_DATA_ERR
	66: "Cannot open input",                      // EX_NO_INPUT
	67: "Addressee unknown",                      // EX_NO_USER
	68: "Host name unknown",                      // EX_NO_HOST
	69: "Service unavailable",                    // EX_UNAVAILABLE
	70: "Internal software error",                // EX_SOFTWARE
	71: "System error",                           // EX_OSERR
	72: "Critical OS file missing",               // EX_OSFILE
	73: "Can't create (user) output file",        // EX_CANTCREAT
	74: "Input/output error",                     // EX_IOERR
	75: "Temp failure; user is invited to retry", // EX_TEMPFAIL
	76: "Remote error in protocol",               // EX_PROTOCOL
	77: "Permission denied",                      // EX_NOPERM
	78: "Configuration error",                    // EX_CONFIG
	79: "Read timeout",                           // EX_TIMEOUT
}

// Temporary hack to write tests.
var testConnHook net.Conn

// send a command to spamd.
func (c *Client) send(
	ctx context.Context,
	cmd string,
	message io.Reader,
	headers Header,
) (io.ReadCloser, error) {

	var conn net.Conn
	if testConnHook != nil {
		conn = testConnHook
	} else {
		var err error
		conn, err = c.dial(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not dial to %v: %v", c.host, err)
		}
	}

	if err := c.write(conn, cmd, message, headers); err != nil {
		return nil, err
	}

	return conn, nil
}

// write the command to the connection.
func (c *Client) write(
	conn net.Conn,
	cmd string,
	message io.Reader,
	headers Header,
) error {

	if strings.TrimSpace(cmd) == "" {
		return errors.New("empty command")
	}

	if headers == nil {
		headers = make(Header)
	}
	if _, ok := headers[HeaderUser]; !ok && c.DefaultUser != "" {
		headers[HeaderUser] = c.DefaultUser
	}

	buf := bytes.NewBufferString("")
	tp := textproto.NewWriter(bufio.NewWriter(buf))

	// Attempt to get the size if it wasn't explicitly given.
	if _, ok := headers[HeaderContentLength]; !ok {
		size, err := sizeFromReader(message)
		if err != nil {
			return fmt.Errorf("could not determine size of message: %v", err)
		}
		headers[HeaderContentLength] = fmt.Sprintf("%v", size)
	}

	err := tp.PrintfLine("%v SPAMC/%v", cmd, clientProtocolVersion)
	if err != nil {
		return err
	}

	// Write headers in deterministic order.
	for _, k := range allHeaders {
		if v, ok := headers[k]; ok {
			err := tp.PrintfLine("%v: %v", k, v)
			if err != nil {
				return err
			}
		}
	}

	if err := tp.PrintfLine(""); err != nil {
		return err
	}
	if err := tp.W.Flush(); err != nil {
		return err
	}

	// Write to spamd.
	if _, err := io.Copy(conn, io.MultiReader(buf, message)); err != nil {
		conn.Close() // nolint: errcheck
		return fmt.Errorf("could not send to spamd: %v", err)
	}

	// Close connection for writing; this makes sure all buffered data is sent.
	switch cc := conn.(type) {
	case *net.TCPConn:
		return cc.CloseWrite()
	case *net.UnixConn:
		return cc.CloseWrite()
	}

	return nil
}

func sizeFromReader(r io.Reader) (int64, error) {
	switch v := r.(type) {
	case *strings.Reader:
		return v.Size(), nil
	case *bytes.Reader:
		return v.Size(), nil
	case *os.File:
		stat, err := v.Stat()
		if err != nil {
			return 0, err
		}
		return stat.Size(), nil
	default:
		return 0, fmt.Errorf("unknown type: %T", v)
	}

}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.host)
	if err != nil {
		if conn != nil {
			conn.Close() // nolint: errcheck
		}
		return nil, fmt.Errorf("could not connect to spamd: %v", err)
	}

	// Set connection timeout
	err = conn.SetDeadline(time.Now().Add(c.dialer.Timeout))
	if err != nil {
		conn.Close() // nolint: errcheck
		return nil, fmt.Errorf("connection to spamd timed out: %v", err)
	}

	return conn, nil
}

// The spamd protocol is a HTTP-esque protocol; a response's first line is the
// response code:
//
//     SPAMD/1.1 0 EX_OK\r\n
//
// Next, it can set some headers:
//
//     Content-length: <size>\r\n
//
// After a blank line we get the response body, which is different for the
// various commands.
//
// A non-0 (or EX_OK) status code is considered an error.
func readResponse(read io.Reader) (headers Header, body string, err error) {
	data := bufio.NewReader(read)
	tp := textproto.NewReader(data)

	// We can't use textproto's ReadCodeLine() here, as SA's response is not
	// quite compatible.
	if err := parseCodeLine(tp, false); err != nil {
		return nil, "", err
	}

	tpHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, "", fmt.Errorf("could not read headers: %v", err)
	}

	headers = make(Header)
	for k, v := range tpHeader {
		headers[k] = v[0]
	}

	body, err = readBody(tp)
	if err != nil {
		return nil, "", fmt.Errorf("could not read body: %v", err)
	}

	return headers, body, nil
}

func parseCodeLine(tp *textproto.Reader, isPing bool) error {
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}

	if len(line) < 11 {
		return fmt.Errorf("short response: %v", line)
	}
	if !strings.HasPrefix(line, "SPAMD/") {
		return fmt.Errorf("unrecognised response: %v", line)
	}

	version := line[6:9]

	// The PING command is special as it will return the *client* version,
	// rather than the server version.
	if isPing {
		if version != clientProtocolVersion {
			return fmt.Errorf("unexpected version: %v; we expected %v",
				version, clientProtocolVersion)
		}
	} else {
		// in some errors it uses version 1.0, so accept both 1.0 and 1.1.
		//     spamd/1.0 76 bad header line: asdasd
		if !supportedVersion(version) {
			return fmt.Errorf("unknown server protocol version %v; we only understand versions %v",
				version, serverProtocolVersions)
		}
	}

	s := strings.Split(line[10:], " ")
	code, err := strconv.Atoi(s[0])
	if err != nil {
		return fmt.Errorf("could not parse return code: %v", err)
	}
	if code != 0 {
		text := strings.Join(s[1:], " ")
		if msg, ok := errorMessages[code]; ok {
			return fmt.Errorf("spamd returned code %v: %v: %v", code, msg, text)
		}
		return fmt.Errorf("spamd returned code %v: %v", code, text)
	}

	return nil
}

func supportedVersion(v string) bool {
	for i := range serverProtocolVersions {
		if serverProtocolVersions[i] == v {
			return true
		}
	}
	return false
}

func readBody(tp *textproto.Reader) (string, error) {
	body := ""
loop:
	for {
		line, err := tp.ReadLine()
		switch err {
		case nil:
			// Do nothing
		case io.EOF:
			break loop
		default:
			return "", err
		}

		body += line + "\r\n"
	}

	return body, nil
}

// Parse the Spam: response header:
//    Spam <yes|no> ; <score> / <base-score>
// example:
//    Spam: yes ; 6.66 / 5.0
func parseSpamHeader(respHeaders Header) (bool, float64, float64, error) {
	spam, ok := respHeaders[HeaderSpam]
	if !ok || len(spam) == 0 {
		return false, 0, 0, errors.New("header missing")
	}

	if len(spam) == 0 {
		return false, 0, 0, errors.New("header empty")
	}

	s := strings.Split(spam, ";")
	if len(s) != 2 {
		return false, 0, 0, fmt.Errorf("unexpected data: %v", spam[0])
	}

	isSpam := false
	switch strings.ToLower(strings.TrimSpace(s[0])) {
	case "true", "yes":
		isSpam = true
	case "false", "no":
		isSpam = false
	default:
		return false, 0, 0, fmt.Errorf("unknown spam status: %v", s[0])
	}

	split := strings.Split(s[1], "/")
	if len(split) != 2 {
		return false, 0, 0, fmt.Errorf("unexpected data: %v", s[1])
	}
	score, err := strconv.ParseFloat(strings.TrimSpace(split[0]), 64)
	if err != nil {
		return false, 0, 0, fmt.Errorf("could not parse spam score: %v", err)
	}
	baseScore, err := strconv.ParseFloat(strings.TrimSpace(split[1]), 64)
	if err != nil {
		return false, 0, 0, fmt.Errorf("could not parse base spam score: %v", err)
	}

	return isSpam, score, baseScore, nil
}
