// Package spamc is a client library for SpamAssassin's spamd daemon.
package spamc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Error codes.
const (
	ExOK          = 0  // no problems
	ExUsage       = 64 // command line usage error
	ExDataErr     = 65 // data format error
	ExNoInput     = 66 // cannot open input
	ExNoUser      = 67 // addressee unknown
	ExNoHost      = 68 // host name unknown
	ExUnavailable = 69 // service unavailable
	ExSoftware    = 70 // internal software error
	ExOserr       = 71 // system error (e.g., can't fork)
	ExOsfile      = 72 // critical OS file missing
	ExCantcreat   = 73 // can't create (user) output file
	ExIoerr       = 74 // input/output error
	ExTempfail    = 75 // temp failure; user is invited to retry
	ExProtocol    = 76 // remote error in protocol
	ExNoperm      = 77 // permission denied
	ExConfig      = 78 // configuration error
	ExTimeout     = 79 // read timeout
)

// Default parameters.
const (
	ProtocolVersion = "1.5"
	DefaultTimeout  = 10
)

// Command types.
const (
	Check               = "CHECK"
	Symbols             = "SYMBOLS"
	Report              = "REPORT"
	ReportIgnorewarning = "REPORT_IGNOREWARNING"
	ReportIfspam        = "REPORT_IFSPAM"
	Skip                = "SKIP"
	Ping                = "PING"
	Tell                = "TELL"
	Process             = "PROCESS"
	Headers             = "HEADERS"
)

// Learn types
const (
	LearnSpam    = "SPAM"
	LearnHam     = "HAM"
	LearnNotspam = "NOTSPAM"
	LearnNotSpam = "NOT_SPAM"
	LearnForget  = "FORGET"
)

// Test Types
const (
	TestInfo    = "info"
	TestBody    = "body"
	TestRawbody = "rawbody"
	TestHeader  = "header"
	TestFull    = "full"
	TestURI     = "uri"
	TestTxt     = "text"
)

// only for parse use !important
const (
	Split     = "§"
	TableMark = "----"
)

// SpamDError is a mapping of the error codes to the error messages.
var SpamDError = map[int]string{
	ExUsage:       "Command line usage error",
	ExDataErr:     "Data format error",
	ExNoInput:     "Cannot open input",
	ExNoUser:      "Addressee unknown",
	ExNoHost:      "Host name unknown",
	ExUnavailable: "Service unavailable",
	ExSoftware:    "Internal software error",
	ExOserr:       "System error",
	ExOsfile:      "Critical OS file missing",
	ExCantcreat:   "Can't create (user) output file",
	ExIoerr:       "Input/output error",
	ExTempfail:    "Temp failure; user is invited to retry",
	ExProtocol:    "Remote error in protocol",
	ExNoperm:      "Permission denied",
	ExConfig:      "Configuration error",
	ExTimeout:     "Read timeout",
}

// Client is a connection to the spamd daemon.
type Client struct {
	ConnTimoutSecs  int
	ProtocolVersion string
	Host            string
	User            string
}

// SpamDOut is the default response struct.
type SpamDOut struct {
	Code    int
	Message string
	Vars    map[string]interface{}
}

// FnCallback for the SpamD response.
type FnCallback func(*bufio.Reader) (*SpamDOut, error)

// New instance of Client.
func New(host string, timeout int) *Client {
	return &Client{timeout, ProtocolVersion, host, ""}
}

// SetUnixUser sets the "User" on the client.
func (s *Client) SetUnixUser(user string) {
	s.User = user
}

// Ping returns a confirmation that spamd is alive.
func (s *Client) Ping() (r *SpamDOut, err error) {
	return s.simpleCall(Ping, []string{})
}

// Check if the passed message is spam or not and return score
func (s *Client) Check(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(Check, msgpars)
}

// Skip ignores this message: client opened connection then changed its mind.
func (s *Client) Skip(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(Skip, msgpars)
}

// Symbols check if message is spam, and return score plus list of symbols hit.
func (s *Client) Symbols(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(Symbols, msgpars)
}

// Report the message is spam, and return score plus report
func (s *Client) Report(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(Report, msgpars)
}

// ReportIgnoreWarning checks if message is spam or not, and return score plus report
func (s *Client) ReportIgnoreWarning(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(ReportIgnorewarning, msgpars)
}

// ReportIfSpam check if message is spam or not, and return score plus report if
// the message is spam.
func (s *Client) ReportIfSpam(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(ReportIfspam, msgpars)
}

// Process this message and return a modified message - on deloy
func (s *Client) Process(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(Process, msgpars)
}

// Headers is the same as PROCESS, but return only modified headers, not body
// (new in protocol 1.4).
func (s *Client) Headers(msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(Headers, msgpars)
}

// ReportingSpam signs the message as spam.
func (s *Client) ReportingSpam(msgpars ...string) (reply *SpamDOut, err error) {
	headers := map[string]string{
		"Message-class": "spam",
		"Set":           "local,remote",
	}
	return s.Tell(msgpars, &headers)
}

// RevokeSpam signs the message as false-positive.
func (s *Client) RevokeSpam(msgpars ...string) (reply *SpamDOut, err error) {
	headers := map[string]string{
		"Message-class": "ham",
		"Set":           "local,remote",
	}
	return s.Tell(msgpars, &headers)
}

// Learn if a message is spam or not
func (s *Client) Learn(learnType string, msgpars ...string) (reply *SpamDOut, err error) {
	headers := make(map[string]string)
	switch strings.ToUpper(learnType) {
	case LearnSpam:
		headers["Message-class"] = "spam"
		headers["Set"] = "local"
	case LearnHam, LearnNotspam, LearnNotSpam:
		headers["Message-class"] = "ham"
		headers["Set"] = "local"
	case LearnForget:
		headers["Remove"] = "local"
	default:
		err = errors.New("Learn Type Not Found")
		return
	}
	return s.Tell(msgpars, &headers)
}

// wrapper to simple calls
func (s *Client) simpleCall(cmd string, msgpars []string) (reply *SpamDOut, err error) {
	return s.call(cmd, msgpars, func(data *bufio.Reader) (r *SpamDOut, e error) {
		r, e = processResponse(cmd, data)
		if r.Code == ExOK {
			e = nil
		}
		return
	}, nil)
}

// SimpleCall is an external wrapper to simple call.
func (s *Client) SimpleCall(cmd string, msgpars ...string) (reply *SpamDOut, err error) {
	return s.simpleCall(strings.ToUpper(cmd), msgpars)
}

// Tell what type of we are to process and what should be done
// with that message.  This includes setting or removing a local
// or a remote database (learning, reporting, forgetting, revoking)
func (s *Client) Tell(msgpars []string, headers *map[string]string) (reply *SpamDOut, err error) {
	return s.call(Tell, msgpars, func(data *bufio.Reader) (r *SpamDOut, e error) {
		r, e = processResponse(Tell, data)

		if r.Code == ExUnavailable {
			e = errors.New("TELL commands are not enabled, set the --allow-tell switch")
			return
		}
		if r.Code == ExOK {
			e = nil
			return
		}
		return
	}, headers)
}

// here a TCP socket is created to call SPAMD
func (s *Client) call(cmd string, msgpars []string, onData FnCallback, extraHeaders *map[string]string) (reply *SpamDOut, err error) {

	if extraHeaders == nil {
		extraHeaders = &map[string]string{}
	}

	switch len(msgpars) {
	case 1:
		if s.User != "" {
			x := *extraHeaders
			x["User"] = s.User
			*extraHeaders = x
		}
	case 2:
		x := *extraHeaders
		x["User"] = msgpars[1]
		*extraHeaders = x
	default:
		if cmd != Ping {
			err = errors.New("Message parameters wrong size")
		} else {
			msgpars = []string{""}
		}
		return
	}

	if cmd == ReportIgnorewarning {
		cmd = Report
	}

	// Create a new connection
	stream, err := net.Dial("tcp", s.Host)

	if err != nil {
		err = errors.New("Connection dial error to spamd: " + err.Error())
		return
	}
	// Set connection timeout
	timeout := time.Now().Add(time.Duration(s.ConnTimoutSecs) * time.Duration(time.Second))
	errTimeout := stream.SetDeadline(timeout)
	if errTimeout != nil {
		err = errors.New("Connection to spamd Timed Out:" + errTimeout.Error())
		return
	}
	defer stream.Close()

	// Create Command to Send to spamd
	cmd += " SPAMC/" + s.ProtocolVersion + "\r\n"
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
		err = errors.New("spamd returned a error: " + errwrite.Error())
		return
	}

	// Execute onData callback throwing the buffer like parameter
	reply, err = onData(bufio.NewReader(stream))
	return
}

// SpamD reply processor
func processResponse(cmd string, data *bufio.Reader) (returnObj *SpamDOut, err error) {
	defer func() {
		data.UnreadByte()
	}()

	returnObj = new(SpamDOut)
	returnObj.Code = -1
	// read the first line
	line, _, _ := data.ReadLine()
	lineStr := string(line)

	r := regexp.MustCompile(`(?i)SPAMD\/([0-9\.]+)\s([0-9]+)\s([0-9A-Z_]+)`)
	var result = r.FindStringSubmatch(lineStr)
	if len(result) < 4 {
		if cmd != "SKIP" {
			err = errors.New("spamd unreconized reply:" + lineStr)
		} else {
			returnObj.Code = ExOK
			returnObj.Message = "SKIPPED"
		}
		return
	}
	returnObj.Code, _ = strconv.Atoi(result[2])
	returnObj.Message = result[3]

	// verify a mapped error...
	if SpamDError[returnObj.Code] != "" {
		err = errors.New(SpamDError[returnObj.Code])
		returnObj.Vars = make(map[string]interface{})
		returnObj.Vars["error_description"] = SpamDError[returnObj.Code]
		return
	}
	returnObj.Vars = make(map[string]interface{})

	// start didSet
	if cmd == Tell {
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
		return
	}
	// read the second line
	line, _, err = data.ReadLine()

	// finish here if line is empty
	if len(line) == 0 {
		if err == io.EOF {
			err = nil
		}
		return
	}

	// ignore content-length header..
	lineStr = string(line)
	switch cmd {

	case Symbols, Check, Report, ReportIfspam, ReportIgnorewarning, Process, Headers:

		switch cmd {
		case Symbols, Report, ReportIfspam, ReportIgnorewarning, Process, Headers:
			// ignore content-length header..
			line, _, err = data.ReadLine()
			lineStr = string(line)
		}

		r := regexp.MustCompile(`(?i)Spam:\s(True|False|Yes|No)\s;\s([0-9\.]+)\s\/\s([0-9\.]+)`)
		var result = r.FindStringSubmatch(lineStr)

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
		case Process, Headers:
			lines := ""
			for {
				line, _, err = data.ReadLine()
				if err == io.EOF || err != nil {
					if err == io.EOF {
						err = nil
					}
					return
				}
				lines += string(line) + "\r\n"
				returnObj.Vars["body"] = lines
			}
		case Symbols:
			// ignore line break...
			data.ReadLine()
			// read
			line, _, err = data.ReadLine()
			returnObj.Vars["symbolList"] = strings.Split(string(line), ",")

		case Report, ReportIfspam, ReportIgnorewarning:
			// ignore line break...
			data.ReadLine()

			for {
				line, _, err = data.ReadLine()

				if len(line) > 0 {
					lineStr = string(line)

					// TXT Table found, prepare to parse..
					if lineStr[0:4] == TableMark {

						section := []map[string]interface{}{}
						tt := 0
						for {
							line, _, err = data.ReadLine()
							// Stop read the text table if last line or Void line
							if err == io.EOF || err != nil || len(line) == 0 {
								if err == io.EOF {
									err = nil
								}
								break
							}
							// Parsing
							lineStr = string(line)
							spc := 2
							if lineStr[0:1] == "-" {
								spc = 1
							}
							lineStr = strings.Replace(lineStr, " ", Split, spc)
							lineStr = strings.Replace(lineStr, " ", Split, 1)
							if spc > 1 {
								lineStr = " " + lineStr[2:]
							}
							x := strings.Split(lineStr, Split)
							if lineStr[1:3] == Split {
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
						if ReportIgnorewarning == cmd {
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
						err = nil
					}
					break
				}
			}
		}
	}

	if err != io.EOF {
		for {
			line, _, err = data.ReadLine()
			if err == io.EOF || err != nil {
				if err == io.EOF {
					err = nil
				}
				break
			}
		}
	}
	return
}
