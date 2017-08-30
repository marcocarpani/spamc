package spamc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	clientProtocolVersion = "1.5"
	serverProtocolVersion = "1.1"
	defaultTimeout        = 20 * time.Second

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

// wrapper to simple calls
func (c *Client) simpleCall(cmd string, msgpars []string) (*Response, error) {
	read, err := c.call(cmd, msgpars, nil)
	defer read.Close() // nolint: errcheck
	if err != nil {
		return nil, err
	}

	r, err := processResponse(cmd, read)
	if r.Code == 0 {
		err = nil
	}
	return r, err
}

// Open a connection to spamd and send a command.
//
// It returns a reader from which you can read spamd's response.
func (c *Client) call(
	cmd string,
	msgpars []string,
	extraHeaders *map[string]string,
) (io.ReadCloser, error) {

	if extraHeaders == nil {
		extraHeaders = &map[string]string{}
	}

	switch len(msgpars) {
	case 1:
		if c.User != "" {
			x := *extraHeaders
			x["User"] = c.User
			*extraHeaders = x
		}
	case 2:
		x := *extraHeaders
		x["User"] = msgpars[1]
		*extraHeaders = x
	default:
		if cmd != CmdPing {
			return nil, errors.New("message parameters wrong size")
		}
		msgpars = []string{""}
	}

	if cmd == CmdReportIgnorewarning {
		cmd = CmdReport
	}

	// Create a new connection
	stream, err := net.DialTimeout("tcp", c.host, c.timeout)
	if err != nil {
		if stream != nil {
			stream.Close() // nolint: errcheck
		}
		return nil, fmt.Errorf("connection dial error to spamd: %v", err)
	}
	// Set connection timeout
	errTimeout := stream.SetDeadline(time.Now().Add(c.timeout))
	if errTimeout != nil {
		stream.Close() // nolint: errcheck
		return nil, fmt.Errorf("connection to spamd timed out: %v", errTimeout)
	}

	// Create Command to Send to spamd
	cmd += " SPAMC/" + clientProtocolVersion + "\r\n"
	cmd += "Content-length: " + fmt.Sprintf("%v\r\n", len(msgpars[0])+2)
	// Process Extra Headers if Any
	if len(*extraHeaders) > 0 {
		for hname, hvalue := range *extraHeaders {
			cmd = cmd + hname + ": " + hvalue + "\r\n"
		}
	}
	cmd += "\r\n" + msgpars[0] + "\r\n\r\n"

	_, errwrite := stream.Write([]byte(cmd))
	if errwrite != nil {
		stream.Close() // nolint: errcheck
		return nil, errors.New("spamd returned a error: " + errwrite.Error())
	}

	return stream, nil
}

var (
	reParseResponse = regexp.MustCompile(`(?i)SPAMD\/([0-9\.\-]+)\s([0-9]+)\s([0-9A-Z_]+)`)
	reFindScore     = regexp.MustCompile(`(?i)Spam:\s(True|False|Yes|No)\s;\s(-?[0-9\.]+)\s\/\s(-?[0-9\.]+)`)
)

// SpamD reply processor.
func processResponse(cmd string, read io.Reader) (*Response, error) {
	data := bufio.NewReader(read)
	defer data.UnreadByte() // nolint: errcheck

	returnObj := new(Response)
	returnObj.Code = -1
	// read the first line
	line, _, _ := data.ReadLine()
	lineStr := string(line)
	var err error

	var result = reParseResponse.FindStringSubmatch(lineStr)
	if len(result) < 4 {
		if cmd != "SKIP" {
			err = errors.New("spamd unrecognised reply:" + lineStr)
		} else {
			returnObj.Code = 0
			returnObj.Message = "SKIPPED"
		}
		return returnObj, err
	}
	returnObj.Code, _ = strconv.Atoi(result[2])
	returnObj.Message = result[3]

	// verify a mapped error...
	if errorMessages[returnObj.Code] != "" {
		err = errors.New(errorMessages[returnObj.Code])
		returnObj.Vars = make(map[string]interface{})
		returnObj.Vars["error_description"] = errorMessages[returnObj.Code]
		return returnObj, err
	}
	returnObj.Vars = make(map[string]interface{})

	// start didSet
	if cmd == CmdTell {
		returnObj.Vars["didSet"] = false
		returnObj.Vars["didRemove"] = false
		for {
			line, _, err = data.ReadLine()

			if err == io.EOF || err != nil {
				if err == io.EOF {
					err = nil
				}
				break
			}
			if strings.Contains(string(line), "DidRemove") {
				returnObj.Vars["didRemove"] = true
			}
			if strings.Contains(string(line), "DidSet") {
				returnObj.Vars["didSet"] = true
			}

		}
		return returnObj, err
	}
	// read the second line
	line, _, err = data.ReadLine()

	// finish here if line is empty
	if len(line) == 0 {
		if err == io.EOF {
			err = nil
		}
		return returnObj, err
	}

	// ignore content-length header..
	lineStr = string(line)
	switch cmd {

	case CmdSymbols,
		//CmdCheck,
		CmdReport,
		CmdReportIfspam,
		CmdReportIgnorewarning,
		CmdProcess,
		CmdHeaders:

		switch cmd {
		case CmdSymbols, CmdReport, CmdReportIfspam, CmdReportIgnorewarning, CmdProcess, CmdHeaders:
			// ignore content-length header..
			line, _, err = data.ReadLine()
			lineStr = string(line)
		}

		var result = reFindScore.FindStringSubmatch(lineStr)

		if len(result) > 0 {
			returnObj.Vars["isSpam"] = false
			switch result[1][0:1] {
			case "T", "t", "Y", "y":
				returnObj.Vars["isSpam"] = true
			}
			returnObj.Vars["spamScore"], _ = strconv.ParseFloat(result[2], 64)
			returnObj.Vars["baseSpamScore"], _ = strconv.ParseFloat(result[3], 64)
		}

		switch cmd {
		case CmdProcess, CmdHeaders:
			lines := ""
			for {
				line, _, err = data.ReadLine()
				if err == io.EOF || err != nil {
					if err == io.EOF {
						err = nil
					}
					return returnObj, err
				}
				lines += string(line) + "\r\n"
				returnObj.Vars["body"] = lines
			}
		case CmdSymbols:
			// ignore line break...
			_, _, err := data.ReadLine()
			if err != nil {
				return nil, err
			}

			// read
			line, _, err = data.ReadLine()
			if err != nil {
				return nil, err
			}
			returnObj.Vars["symbolList"] = strings.Split(string(line), ",")

		case CmdReport, CmdReportIfspam, CmdReportIgnorewarning:
			// ignore line break...
			_, _, err := data.ReadLine()
			if err != nil {
				return nil, err
			}

			for {
				line, _, err = data.ReadLine()

				if len(line) > 0 {
					lineStr = string(line)

					// TXT Table found, prepare to parse..
					if len(lineStr) >= 4 && lineStr[0:4] == tableMark {

						section := []map[string]interface{}{}
						tt := 0
						for {
							line, _, err = data.ReadLine()
							// Stop read the text table if last line or Void line
							if err == io.EOF || err != nil || len(line) == 0 {
								if err == io.EOF {
									err = nil // nolint: ineffassign
								}
								break
							}
							// Parsing
							lineStr = string(line)
							spc := 2
							if lineStr[0:1] == "-" {
								spc = 1
							}
							lineStr = strings.Replace(lineStr, " ", split, spc)
							lineStr = strings.Replace(lineStr, " ", split, 1)
							if spc > 1 {
								lineStr = " " + lineStr[2:]
							}
							x := strings.Split(lineStr, split)
							if lineStr[1:3] == split {
								section[tt-1]["message"] = fmt.Sprintf("%v %v", section[tt-1]["message"], strings.TrimSpace(lineStr[5:]))
							} else {
								if len(x) != 0 {
									message := strings.TrimSpace(x[2])
									score, _ := strconv.ParseFloat(strings.TrimSpace(x[0]), 64)

									section = append(section, map[string]interface{}{
										"score":   score,
										"symbol":  x[1],
										"message": message,
									})

									tt++
								}
							}
						}
						if cmd == CmdReportIgnorewarning {
							nsection := []map[string]interface{}{}
							for _, c := range section {
								if c["score"].(float64) != 0 {
									nsection = append(nsection, c)
								}
							}
							section = nsection
						}

						returnObj.Vars["report"] = section
						break
					}
				}

				if err == io.EOF || err != nil {
					if err == io.EOF {
						err = nil // nolint: ineffassign
					}
					break
				}
			}
		}
	}

	if err != io.EOF {
		for {
			line, _, err = data.ReadLine() // nolint: ineffassign
			if err == io.EOF || err != nil {
				if err == io.EOF {
					err = nil
				}
				break
			}
		}
	}
	return returnObj, err
}

func (c *Client) dial() (net.Conn, error) {
	// Create a new connection
	conn, err := net.DialTimeout("tcp", c.host, c.timeout)
	if err != nil {
		if conn != nil {
			conn.Close() // nolint: errcheck
		}
		return nil, fmt.Errorf("could not connect to spamd: %v", err)
	}

	// Set connection timeout
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		conn.Close() // nolint: errcheck
		return nil, fmt.Errorf("connection to spamd timed out: %v", err)
	}

	return conn, nil
}

func (c *Client) write(conn net.Conn, cmd, message, user string, headers textproto.MIMEHeader) error {
	buf := bytes.NewBufferString("")
	w := bufio.NewWriter(buf)
	tp := textproto.NewWriter(w)
	tp.PrintfLine("SPAMC/%v", clientProtocolVersion)
	tp.PrintfLine("Content-Length: %v", len(message)+2)
	// TODO: Write user?
	for k, vals := range headers {
		for _, v := range vals {
			tp.PrintfLine("%v: %v", k, v)
		}
	}
	tp.PrintfLine("")
	tp.W.WriteString(strings.TrimSpace(message) + "\r\n")
	tp.W.Flush()

	d, _ := ioutil.ReadAll(buf)
	if _, err := conn.Write(d); err != nil {
		conn.Close() // nolint: errcheck
		return errors.New("spamd returned a error: " + err.Error())
	}

	return nil
}

// send a command to spamd.
func (c *Client) send(cmd, message, user string, headers textproto.MIMEHeader) (io.ReadCloser, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("could not dial to %v: %v", c.host, err)
	}

	if err := c.write(conn, cmd, message, user, headers); err != nil {
		return nil, err
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
// The only defined header at this moment is Content-Length.
//
// After a blank line we get the response body, which is different for the
// various commands.
//
// A non-0 (or EX_OK) status code is considered an error.
func readResponse(read io.Reader) (headers textproto.MIMEHeader, body string, err error) {
	data := bufio.NewReader(read)
	tp := textproto.NewReader(data)

	// We can't use textproto's ReadCodeLine() here, as SA's response is not
	// quite compatible.
	if err := parseCodeLine(tp); err != nil {
		return nil, "", err
	}

	headers, err = tp.ReadMIMEHeader()
	if err != nil {
		return nil, "", err
	}

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
		if msg, ok := errorMessages[code]; ok {
			return fmt.Errorf("spamd returned code %v: %v", code, msg)
		}

		return fmt.Errorf("spamd returned code %v: %v",
			code, strings.Join(s[1:], " "))
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
