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
	message io.ReadSeeker,
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

// rearrangeMessageReader will rearrange the message reader to make sure SA will understand the message
func (c Client) rearrangeMessageReader(message io.ReadSeeker, size int64) (io.Reader, int64, error) {
	var headers bytes.Buffer
	var rest bytes.Buffer

	isASCII := func(m []byte) bool {
		for _, c := range m {
			if c > 127 {
				return false
			}
		}
		return true
	}

	r := bufio.NewReader(message)

	var returnError error

	// we assume that there is no newline between headers and body, so increment size
	size += 2

	for {
		chars, err := r.Peek(2)
		if err != nil {
			returnError = err
			break
		}
		if bytes.Equal(chars, []byte("\r\n")) {
			// we were wrong there was a newline between headers and body
			// decrement size
			size -= 2
			// read and discard it, and we are done
			r.Read(make([]byte, 2))
			break
		}
		if chars[0] == ' ' || chars[0] == '\t' {
			// if we have a previous key append value, and continue
			// if not we are not reading headers
			if headers.Len() > 0 {
				line, err := r.ReadSlice('\n')
				if err != nil {
					rest.Write(line)
					returnError = err
					break
				}
				if !isASCII(line) {
					rest.Write(line)
					returnError = errors.New("non ascii characters found: [" + string(line) + "]")
					break
				}
				headers.Write(line)
				continue
			} else {
				// this line start with whitespace but there is no
				// previous header to append, so it's not a header
				returnError = errors.New("multiline header part found without first header")
				break
			}
		}

		// it should be a header read it
		line, err := r.ReadSlice('\n')

		if err != nil {
			rest.Write(line)
			returnError = err
			break
		}
		// Check for a key, we must have one for it to be a header
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			rest.Write(line)
			returnError = errors.New("malformed MIME header line: [" + string(line) + "]")
			break
		}
		if !isASCII(line) {
			rest.Write(line)
			returnError = errors.New("non ascii characters found: [" + string(line) + "]")
			break
		}
		headers.Write(line)
	}

	// isTerminated will check last characters of the reader for end of line
	isTerminated := func(message io.ReadSeeker) (bool, error) {
		// make sure to seek back to the current position or
		// we mess up the internal message pointer
		current, _ := message.Seek(0, io.SeekCurrent)
		defer message.Seek(current, io.SeekStart)

		_, err := message.Seek(-2, io.SeekEnd)

		if err != nil {
			return false, err
		}
		buf := make([]byte, 2)
		_, err = message.Read(buf)
		if err != nil {
			return false, err
		}
		if bytes.Equal(buf, []byte("\r\n")) {
			// and we are done, its terminated
			return true, nil
		}
		return false, nil
	}

	messageTerminated, err := isTerminated(message)
	if err != nil {
		returnError = err
	}

	end := ""
	if !messageTerminated {
		size += 2
		end = "\r\n"
	}

	resultReader := io.MultiReader(
		bufio.NewReader(&headers),
		strings.NewReader("\r\n"),
		bufio.NewReader(&rest),
		r,
		strings.NewReader(end),
	)

	// we might have hit EOF, reset that
	if returnError == io.EOF {
		returnError = nil
	}

	return resultReader, size, returnError
}

// write the command to the connection.
func (c *Client) write(
	conn net.Conn,
	cmd string,
	message io.ReadSeeker,
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

	// Make sure to seek to start of message
	if _, err := message.Seek(0, io.SeekStart); err != nil {
		return err
	}

	size := int64(-1)
	switch v := message.(type) {
	case *strings.Reader:
		size = v.Size()
	case *bytes.Reader:
		size = v.Size()
	case *os.File:
		stat, err := v.Stat()
		if err != nil {
			return err
		}
		size = stat.Size()
	}

	// make sure to delete a present content-length (and use it if
	// we could not set size above
	if _, ok := headers[HeaderContentLength]; ok {
		if size == -1 {
			headerContentLength, err := strconv.ParseInt(headers.Get(HeaderContentLength), 10, 64)
			if err != nil {
				return err
			}
			size = headerContentLength
		}
	}

	// Make the sure message always ends in \r\n, if it doesn't SA will just
	// keep reading from the connection and it will block until it timouts.
	messageReader, messageSize, err := c.rearrangeMessageReader(message, size)

	err = tp.PrintfLine("%v SPAMC/%v", cmd, clientProtocolVersion)
	if err != nil {
		return err
	}

	// Always add Content-length header.
	if messageSize >= 0 {
		err = tp.PrintfLine("Content-length: %v", messageSize)
		if err != nil {
			return err
		}
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

	err = tp.W.Flush()
	if err != nil {
		return err
	}

	// Write to spamd.
	if _, err := io.Copy(conn, io.MultiReader(buf, messageReader)); err != nil {
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
	if err := parseCodeLine(tp, false); err != nil {
		return nil, "", err
	}

	tpHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, "", fmt.Errorf("could not read headers: %v", err)
	}

	headers = Header(tpHeader)

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
	spam, ok := respHeaders["Spam"]
	if !ok || len(spam) == 0 {
		return false, 0, 0, errors.New("header missing")
	}

	if len(spam[0]) == 0 {
		return false, 0, 0, errors.New("header empty")
	}

	s := strings.Split(spam[0], ";")
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
