package spamc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// Command types.
const (
	CmdCheck        = "CHECK"
	CmdSymbols      = "SYMBOLS"
	CmdReport       = "REPORT"
	CmdReportIfspam = "REPORT_IFSPAM"
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
	// DefaultUser is the User to send if a command didn't specify one.
	DefaultUser string

	host   string
	dialer net.Dialer
	conn   net.Conn
}

// Error is used for spamd responses; it contains the spamd exit code.
type Error struct {
	msg  string
	Code int64
	Line string
}

func (e Error) Error() string { return e.msg }

// New instance of Client.
func New(host string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		host: host,
		dialer: net.Dialer{
			Timeout: timeout,
		},
	}
}

// NewWithDialer creates a new instance of Client.
func NewWithDialer(host string, dialer net.Dialer) *Client {
	return &Client{
		host:   host,
		dialer: dialer,
	}
}

// CheckResponse is the response from the Check and Symbols commands.
type CheckResponse struct {
	// IsSpam reports if this message is considered spam.
	IsSpam bool

	// Score is the spam score of this message.
	Score float64

	// BaseScore is the "minimum spam score" configured on the server. This
	// is usually 5.0.
	BaseScore float64

	// Symbols that matches; only when the Symbols command is used.
	Symbols []string
}

// Ping returns a confirmation that spamd is alive.
func (c *Client) Ping(ctx context.Context) error {
	read, err := c.send(ctx, CmdPing, strings.NewReader(""), nil)
	if err != nil {
		return fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	tp := textproto.NewReader(bufio.NewReader(read))
	return parseCodeLine(tp, true)
}

// Check if the passed message is spam.
func (c *Client) Check(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*CheckResponse, error) {

	read, err := c.send(ctx, CmdCheck, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	return &CheckResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
	}, nil
}

// Symbols checks if the message is spam and returns the score and a list of all
// symbols that were hit.
func (c *Client) Symbols(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*CheckResponse, error) {

	// SPAMD/1.1 0 EX_OK
	// Content-length: 50
	// Spam: False ; 1.6 / 5.0
	//
	// INVALID_DATE,MISSING_HEADERS,NO_RECEIVED,NO_RELAYS
	read, err := c.send(ctx, CmdSymbols, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	body, err := readBody(tp)
	if err != nil {
		return nil, fmt.Errorf("could not read body: %v", err)
	}

	return &CheckResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
		Symbols:   strings.Split(strings.TrimSpace(body), ","),
	}, nil
}

// ReportResponse is the response from the Report and ReportIfSpam commands.
type ReportResponse struct {
	// IsSpam reports if this message is considered spam.
	IsSpam bool

	// Score is the spam score of this message.
	Score float64

	// BaseScore is the "minimum spam score" configured on the server. This
	// is usually 5.0.
	BaseScore float64

	// Report broken down in the found rules and their descriptions.
	Report Report
}

// Report gives a detailed textual report for the message.
func (c *Client) Report(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*ReportResponse, error) {
	return c.report(ctx, CmdReport, msg, headers)
}

// ReportIfSpam gives a detailed textual report for the message if it is
// considered spam. If it's not it will set just the spam score.
func (c *Client) ReportIfSpam(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*ReportResponse, error) {
	return c.report(ctx, CmdReportIfspam, msg, headers)
}

// Implement Report and ReportIfSpam
func (c *Client) report(
	ctx context.Context,
	cmd string,
	msg io.Reader,
	headers Header,
) (*ReportResponse, error) {

	read, err := c.send(ctx, cmd, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	report, err := parseReport(tp)
	if err != nil {
		return nil, fmt.Errorf("could not parse report: %v", err)
	}

	return &ReportResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
		Report:    report,
	}, nil
}

// Process this message and return a modified message.
func (c *Client) Process(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*CheckResponse, error) {

	read, err := c.send(ctx, CmdProcess, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	// TODO: Read body

	return &CheckResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
	}, nil
}

// Headers is the same as Process() but returns only modified headers and not
// the body.
func (c *Client) Headers(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*CheckResponse, error) {

	read, err := c.send(ctx, CmdHeaders, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	// TODO: Read body

	return &CheckResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
	}, nil
}

// TellResponse is the response of a TELL command.
type TellResponse struct {
}

// Tell what type of we are to process and what should be done with that
// message.
//
// This includes setting or removing a local or a remote database (learning,
// reporting, forgetting, revoking).
func (c *Client) Tell(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*TellResponse, error) {

	read, err := c.send(ctx, CmdTell, msg, headers)
	defer read.Close() // nolint: errcheck
	if err != nil {
		return nil, err
	}

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	fmt.Printf("%#v\n", respHeaders)

	/*
		if serr, ok := err.(Error); ok && serr.Code == 69 {
			return nil, errors.New(
				"TELL commands are not enabled, set the --allow-tell switch")
		}
	*/

	/*
		returnObj.Vars["didSet"] = false
		returnObj.Vars["didRemove"] = false
		if strings.Contains(string(line), "DidRemove") {
			returnObj.Vars["didRemove"] = true
		}
		if strings.Contains(string(line), "DidSet") {
			returnObj.Vars["didSet"] = true
		}
	*/

	return &TellResponse{}, nil
}

// Learn if a message is spam. This is a more convenient wrapper around SA's
// "TELL" command.
//
// Use one of the Learn* constants as the learnType.
func (c *Client) Learn(
	ctx context.Context,
	learnType string,
	msg io.Reader,
	headers Header,
) (*TellResponse, error) {

	if headers == nil {
		headers = make(Header)
	}
	switch strings.ToUpper(learnType) {
	case LearnSpam:
		headers[HeaderMessageClass] = "spam"
		headers[HeaderSet] = "local"
	case LearnHam:
		headers[HeaderMessageClass] = "ham"
		headers[HeaderSet] = "local"
	case LearnForget:
		headers[HeaderRemove] = "local"
	default:
		return nil, fmt.Errorf("unknown learn type: %v", learnType)
	}
	return c.Tell(ctx, msg, headers)
}
