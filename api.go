package spamc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Command types.
const (
	CmdSymbols      = "SYMBOLS"
	CmdReport       = "REPORT"
	CmdReportIfspam = "REPORT_IFSPAM"
	CmdSkip         = "SKIP"
	CmdPing         = "PING"
	CmdTell         = "TELL"
	CmdProcess      = "PROCESS"
	CmdHeaders      = "HEADERS"
)

// Learn types.
const (
	LearnSpam   = "SPAM"
	LearnHam    = "HAM"
	LearnForget = "FORGET"
)

// Client is a connection to the spamd daemon.
type Client struct {
	timeout     time.Duration
	host        string
	DefaultUser string
}

// Response is the default response struct.
type Response struct {
	Message string
	Vars    map[string]interface{}
}

// Error is used for spamd responses; it contains the spamd exit code.
type Error struct {
	msg  string
	Code int64
}

func (e Error) Error() string { return e.msg }

// New instance of Client.
func New(host string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	return &Client{
		timeout:     timeout,
		host:        host,
		DefaultUser: "",
	}
}

// CheckResponse is the response from the Check command.
type CheckResponse struct {
	Response

	// IsSpam reports if this message is considered spam.
	IsSpam bool

	// SpamScore is the spam score of this message.
	SpamScore float64

	// BaseSpamScore is the "minimum spam score" configured on the server. This
	// is usually 5.0.
	BaseSpamScore float64
}

// Check if the passed message is spam.
func (c *Client) Check(msg string, headers Header) (*CheckResponse, error) {
	read, err := c.call("CHECK", msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	spam, ok := respHeaders["Spam"]
	if !ok || len(spam) == 0 {
		return nil, errors.New("Spam header missing in response")
	}

	r := CheckResponse{}
	s := strings.Split(spam[0], ";")
	if len(s) != 2 {
		return nil, fmt.Errorf("unexpected data: %v", spam[0])
	}

	switch strings.ToLower(strings.TrimSpace(s[0])) {
	case "true", "yes":
		r.IsSpam = true
	case "false", "no":
		r.IsSpam = false
	default:
		return nil, fmt.Errorf("unknown spam status: %v", s[0])
	}

	score := strings.Split(s[1], "/")
	if len(score) != 2 {
		return nil, fmt.Errorf("unexpected data: %v", s[1])
	}
	r.SpamScore, err = strconv.ParseFloat(strings.TrimSpace(score[0]), 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse spam score: %v", err)
	}
	r.BaseSpamScore, err = strconv.ParseFloat(strings.TrimSpace(score[1]), 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse base spam score: %v", err)
	}

	return &r, nil
}

// Symbols check if message is spam and return the score and a list of all
// symbols that were hit.
func (c *Client) Symbols(msg string, headers Header) (*Response, error) {
	return c.simpleCall(CmdSymbols, msg, headers)
}

// Report checks if the message is spam and returns the score plus report.
func (c *Client) Report(msg string, headers Header) (*Response, error) {
	return c.simpleCall(CmdReport, msg, headers)
}

// ReportIfSpam checks if the message is spam and returns the score plus report
// if the message is spam.
func (c *Client) ReportIfSpam(msg string, headers Header) (*Response, error) {
	return c.simpleCall(CmdReportIfspam, msg, headers)
}

// Skip ignores this message: client opened connection then changed its mind.
func (c *Client) Skip(msg string, headers Header) (*Response, error) {
	return c.simpleCall(CmdSkip, msg, headers)
}

// Ping returns a confirmation that spamd is alive.
func (c *Client) Ping() (*Response, error) {
	return c.simpleCall(CmdPing, "", nil)
}

// Process this message and return a modified message.
func (c *Client) Process(msg string, headers Header) (*Response, error) {
	return c.simpleCall(CmdProcess, msg, headers)
}

// Tell what type of we are to process and what should be done with that
// message.
//
// This includes setting or removing a local or a remote database (learning,
// reporting, forgetting, revoking).
func (c *Client) Tell(msg string, headers Header) (*Response, error) {
	read, err := c.call(CmdTell, msg, headers)
	defer read.Close() // nolint: errcheck
	if err != nil {
		return nil, err
	}

	r, err := processResponse(CmdTell, read)
	if err != nil {
		if serr, ok := err.(Error); ok && serr.Code == 69 {
			return nil, errors.New(
				"TELL commands are not enabled, set the --allow-tell switch")
		}

		return nil, err
	}

	return r, nil
}

// Headers is the same as Process() but returns only modified headers and not
// the body.
func (c *Client) Headers(msg string, headers Header) (*Response, error) {
	return c.simpleCall(CmdHeaders, msg, headers)
}

// Learn if a message is spam. This is a more convenient wrapper around SA's
// "TELL" command.
//
// Use one of the Learn* constants as the learnType.
func (c *Client) Learn(learnType, msg string, headers Header) (*Response, error) {
	if headers == nil {
		headers = make(Header)
	}
	switch strings.ToUpper(learnType) {
	case LearnSpam:
		headers.Add(HeaderMessageClass, "spam")
		headers.Add(HeaderSet, "local")
	case LearnHam:
		headers.Add(HeaderMessageClass, "ham")
		headers.Add(HeaderSet, "local")
	case LearnForget:
		headers.Add(HeaderRemove, "local")
	default:
		return nil, fmt.Errorf("unknown learn type: %v", learnType)
	}
	return c.Tell(msg, headers)
}

// SimpleCall sends a command to SpamAssassin.
func (c *Client) SimpleCall(
	cmd, msg string,
	headers Header,
) (*Response, error) {
	return c.simpleCall(strings.ToUpper(cmd), msg, headers)
}
