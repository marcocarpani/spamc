// Package spamc is a client library for SpamAssassin's spamd daemon.
//
// http://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
package spamc

import (
	"errors"
	"fmt"
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

// Command types.
const (
	CmdCheck               = "CHECK"
	CmdSymbols             = "SYMBOLS"
	CmdReport              = "REPORT"
	CmdReportIgnorewarning = "REPORT_IGNOREWARNING"
	CmdReportIfspam        = "REPORT_IFSPAM"
	CmdSkip                = "SKIP"
	CmdPing                = "PING"
	CmdTell                = "TELL"
	CmdProcess             = "PROCESS"
	CmdHeaders             = "HEADERS"
)

// Learn types.
const (
	LearnSpam   = "SPAM"
	LearnHam    = "HAM"
	LearnForget = "FORGET"
)

// Verbose enabled verbose debugging logs to stderr.
var Verbose = false

// Client is a connection to the spamd daemon.
type Client struct {
	timeout         time.Duration
	protocolVersion string
	host            string
	User            string
}

// Response is the default response struct.
type Response struct {
	Code    int
	Message string
	Vars    map[string]interface{}
}

// New instance of Client.
func New(host string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Client{
		timeout:         timeout,
		protocolVersion: protocolVersion,
		host:            host,
		User:            "",
	}
}

// SetUnixUser sets the "User" on the client.
//
// TODO: Document what this does, exactly.
func (s *Client) SetUnixUser(user string) {
	s.User = user
}

// Check if the passed message is spam.
func (s *Client) Check(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdCheck, msgpars)
}

// Symbols check if message is spam and return the score and a list of all
// symbols that were hit.
func (s *Client) Symbols(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdSymbols, msgpars)
}

// Report checks if the message is spam and returns the score plus report.
func (s *Client) Report(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdReport, msgpars)
}

// ReportIfSpam checks if the message is spam and returns the score plus report
// if the message is spam.
func (s *Client) ReportIfSpam(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdReportIfspam, msgpars)
}

// Skip ignores this message: client opened connection then changed its mind.
func (s *Client) Skip(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdSkip, msgpars)
}

// Ping returns a confirmation that spamd is alive.
func (s *Client) Ping() (*Response, error) {
	return s.simpleCall(CmdPing, []string{})
}

// Process this message and return a modified message.
func (s *Client) Process(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdProcess, msgpars)
}

// Tell what type of we are to process and what should be done with that
// message.
//
// This includes setting or removing a local or a remote database (learning,
// reporting, forgetting, revoking).
func (s *Client) Tell(msgpars []string, headers *map[string]string) (*Response, error) {
	read, err := s.call(CmdTell, msgpars, headers)
	defer read.Close() // nolint: errcheck
	if err != nil {
		return nil, err
	}

	r, err := processResponse(CmdTell, read)
	if err != nil {
		return nil, err
	}

	if r.Code == ExUnavailable {
		return nil, errors.New("TELL commands are not enabled, set the --allow-tell switch")
	}

	return r, nil
}

// Headers is the same as Process() but returns only modified headers and not
// the body.
func (s *Client) Headers(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdHeaders, msgpars)
}

// Learn if a message is spam. This is a more convenient wrapper around SA's
// "TELL" command.
//
// Use one of the Learn* constants as the learnType.
func (s *Client) Learn(learnType string, msgpars ...string) (*Response, error) {
	headers := make(map[string]string)
	switch strings.ToUpper(learnType) {
	case LearnSpam:
		headers["Message-class"] = "spam"
		headers["Set"] = "local"
	case LearnHam:
		headers["Message-class"] = "ham"
		headers["Set"] = "local"
	case LearnForget:
		headers["Remove"] = "local"
	default:
		return nil, fmt.Errorf("unknown learn type: %v", learnType)
	}
	return s.Tell(msgpars, &headers)
}

// ReportIgnoreWarning checks if message is spam, and return score plus report
/*
* TODO: Not in spamd protocol? Figure out what this does.
func (s *Client) ReportIgnoreWarning(msgpars ...string) (*Response, error) {
	return s.simpleCall(CmdReportIgnorewarning, msgpars)
}
*/

// SimpleCall sends a command to SpamAssassin.
func (s *Client) SimpleCall(cmd string, msgpars ...string) (*Response, error) {
	return s.simpleCall(strings.ToUpper(cmd), msgpars)
}
