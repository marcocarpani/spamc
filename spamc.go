package spamc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	protocolVersion = "1.5"
	defaultTimeout  = 20 * time.Second

	split     = "§"
	tableMark = "----"
)

// mapping of the error codes to the error messages.
var errorMessages = map[int]string{
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

func dbg(s string, f ...interface{}) {
	if Verbose {
		fmt.Fprintf(os.Stderr, s, f...)
	}
}

// wrapper to simple calls
func (s *Client) simpleCall(cmd string, msgpars []string) (*Response, error) {
	read, err := s.call(cmd, msgpars, nil)
	defer read.Close() // nolint: errcheck
	if err != nil {
		return nil, err
	}

	r, err := processResponse(cmd, read)
	if r.Code == ExOK {
		err = nil
	}
	return r, err
}

// Open a connection to spamd and send a command.
//
// It returns a reader from which you can read spamd's response.
func (s *Client) call(
	cmd string,
	msgpars []string,
	extraHeaders *map[string]string,
) (io.ReadCloser, error) {

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
		if cmd != CmdPing {
			return nil, errors.New("message parameters wrong size")
		}
		msgpars = []string{""}
	}

	if cmd == CmdReportIgnorewarning {
		cmd = CmdReport
	}

	// Create a new connection
	stream, err := net.DialTimeout("tcp", s.host, s.timeout)
	if err != nil {
		stream.Close() // nolint: errcheck
		return nil, fmt.Errorf("connection dial error to spamd: %v", err)
	}
	// Set connection timeout
	errTimeout := stream.SetDeadline(time.Now().Add(s.timeout))
	if errTimeout != nil {
		stream.Close() // nolint: errcheck
		return nil, fmt.Errorf("connection to spamd timed out: %v", errTimeout)
	}

	// Create Command to Send to spamd
	cmd += " SPAMC/" + s.protocolVersion + "\r\n"
	cmd += "Content-length: " + fmt.Sprintf("%v\r\n", len(msgpars[0])+2)
	// Process Extra Headers if Any
	if len(*extraHeaders) > 0 {
		for hname, hvalue := range *extraHeaders {
			cmd = cmd + hname + ": " + hvalue + "\r\n"
		}
	}
	cmd += "\r\n" + msgpars[0] + "\r\n\r\n"

	dbg("sending:\n%v\nsending END\n", cmd)
	_, errwrite := stream.Write([]byte(cmd))
	if errwrite != nil {
		stream.Close() // nolint: errcheck
		return nil, errors.New("spamd returned a error: " + errwrite.Error())
	}

	return stream, nil
}

var (
	reParseResponse = regexp.MustCompile(`(?i)SPAMD\/([0-9\.\-]+)\s([0-9]+)\s([0-9A-Z_]+)`)
	reFindScore     = regexp.MustCompile(`(?i)Spam:\s(True|False|Yes|No)\s;\s([0-9\.]+)\s\/\s([0-9\.]+)`)
)

// SpamD reply processor
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
			returnObj.Code = ExOK
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
		CmdCheck,
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
