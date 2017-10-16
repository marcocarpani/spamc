package spamc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

const (
	clientProtocolVersion = "1.5"
	serverProtocolVersion = "1.1"

	split     = "§"
	tableMark = "----"
)

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
	cmd, message string,
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
	cmd, message string,
	headers Header,
) error {

	if strings.TrimSpace(cmd) == "" {
		return errors.New("empty command")
	}

	if headers == nil {
		headers = make(Header)
	}
	if _, ok := headers[HeaderUser]; !ok && c.DefaultUser != "" {
		headers.Add(HeaderUser, c.DefaultUser)
	}

	buf := bytes.NewBufferString("")
	w := bufio.NewWriter(buf)
	tp := textproto.NewWriter(w)

	err := tp.PrintfLine("%v SPAMC/%v", cmd, clientProtocolVersion)
	if err != nil {
		return err
	}

	// Always add Content-length header.
	err = tp.PrintfLine("Content-length: %v", len(message))
	if err != nil {
		return err
	}

	// Write headers.
	for k, vals := range headers {
		for _, v := range vals {
			err := tp.PrintfLine("%v: %v", k, v)
			if err != nil {
				return err
			}
		}
	}
	err = tp.PrintfLine("")
	if err != nil {
		return err
	}

	// Write body.
	_, err = tp.W.WriteString(message)
	if err != nil {
		return err
	}
	err = tp.W.Flush()
	if err != nil {
		return err
	}

	// Write to spamd.
	d, _ := ioutil.ReadAll(buf)
	if _, err := conn.Write(d); err != nil {
		conn.Close() // nolint: errcheck
		return fmt.Errorf("could not send to spamd: %v", err)
	}
	return nil
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
	if err := parseCodeLine(tp); err != nil {
		return nil, "", err
	}

	tpHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, "", err
	}

	headers = Header(tpHeader)

	body, err = readBody(tp)
	if err != nil {
		return nil, "", err
	}

	return headers, body, nil
}

func parseCodeLine(tp *textproto.Reader) error {
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

	// TODO: in some errors it uses version 1.0:
	//     SPAMD/1.0 76 Bad header line: ASDASD
	if version := line[6:9]; version != serverProtocolVersion {
		return fmt.Errorf("unknown server protocol version %v; we only understand version %v",
			version, serverProtocolVersion)
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
