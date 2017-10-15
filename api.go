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
func (c *Client) Check(msgpars ...string) (*CheckResponse, error) {
	read, err := c.call("CHECK", msgpars, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	headers, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	spam, ok := headers["Spam"]
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
func (c *Client) Symbols(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdSymbols, msgpars)
}

// Report checks if the message is spam and returns the score plus report.
func (c *Client) Report(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdReport, msgpars)
}

// ReportIfSpam checks if the message is spam and returns the score plus report
// if the message is spam.
func (c *Client) ReportIfSpam(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdReportIfspam, msgpars)
}

// Skip ignores this message: client opened connection then changed its mind.
func (c *Client) Skip(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdSkip, msgpars)
}

// Ping returns a confirmation that spamd is alive.
func (c *Client) Ping() (*Response, error) {
	return c.simpleCall(CmdPing, []string{})
}

// Process this message and return a modified message.
func (c *Client) Process(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdProcess, msgpars)
}

// Tell what type of we are to process and what should be done with that
// message.
//
// This includes setting or removing a local or a remote database (learning,
// reporting, forgetting, revoking).
func (c *Client) Tell(msgpars []string, headers *map[string]string) (*Response, error) {
	read, err := c.call(CmdTell, msgpars, headers)
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
func (c *Client) Headers(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdHeaders, msgpars)
}

// Learn if a message is spam. This is a more convenient wrapper around SA's
// "TELL" command.
//
// Use one of the Learn* constants as the learnType.
func (c *Client) Learn(learnType string, msgpars ...string) (*Response, error) {
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
	return c.Tell(msgpars, &headers)
}

// ReportIgnoreWarning checks if message is spam, and return score plus report
/*
* TODO: Not in spamd protocol? Figure out what this does.
func (c *Client) ReportIgnoreWarning(msgpars ...string) (*Response, error) {
	return c.simpleCall(CmdReportIgnorewarning, msgpars)
}
*/

// SimpleCall sends a command to SpamAssassin.
func (c *Client) SimpleCall(cmd string, msgpars ...string) (*Response, error) {
	return c.simpleCall(strings.ToUpper(cmd), msgpars)
}
