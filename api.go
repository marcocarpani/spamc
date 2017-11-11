package spamc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// Client is a connection to the spamd daemon.
type Client struct {
	// DefaultUser is the User to send if a command didn't specify one.
	DefaultUser string

	host   string
	dialer Dialer
	conn   net.Conn
}

// Error is used for spamd responses; it contains the spamd exit code.
type Error struct {
	msg  string
	Code int64  // Code from spamd
	Line string // Line of text from spamd, unaltered.
}

func (e Error) Error() string { return e.msg }

// Dialer to connect to spamd; usually a net.Dialer instance.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Header for requests.
type Header map[string]string

// Header key constants.
const (
	HeaderContentLength = "Content-length"
	HeaderDidRemove     = "Didremove"
	HeaderDidSet        = "Didset"
	HeaderMessageClass  = "Message-class"
	HeaderRemove        = "Remove"
	HeaderSet           = "Set"
	HeaderSpam          = "Spam"
	HeaderUser          = "User"
	MessageClassSpam    = "spam"
	MessageClassHam     = "ham"
	TellLocal           = "local"
	TellRemote          = "remote"
)

// New instance of Client.
func New(host string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		host: host,
		dialer: &net.Dialer{
			Timeout: timeout,
		},
	}
}

// NewWithDialer creates a new instance of Client which connects to spamd with
// the given dialer.
func NewWithDialer(host string, dialer Dialer) *Client {
	return &Client{
		host:   host,
		dialer: dialer,
	}
}

// Ping returns a confirmation that spamd is alive.
func (c *Client) Ping(ctx context.Context) error {
	read, err := c.send(ctx, cmdPing, strings.NewReader(""), nil)
	if err != nil {
		return fmt.Errorf("error sending command to spamd: %v", err)
	}
	defer read.Close() // nolint: errcheck

	tp := textproto.NewReader(bufio.NewReader(read))
	return parseCodeLine(tp, true)
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

// Check if the passed message is spam.
func (c *Client) Check(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*CheckResponse, error) {

	read, err := c.send(ctx, cmdCheck, msg, headers)
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
	read, err := c.send(ctx, cmdSymbols, msg, headers)
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

	s := strings.Split(strings.TrimSpace(body), ",")
	// Special case when symbols list is empty.
	if len(s) == 1 && s[0] == "" {
		s = *new([]string)
	}

	return &CheckResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
		Symbols:   s,
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
	return c.report(ctx, cmdReport, msg, headers)
}

// ReportIfSpam gives a detailed textual report for the message if it is
// considered spam. If it's not it will set just the spam score.
func (c *Client) ReportIfSpam(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*ReportResponse, error) {
	return c.report(ctx, cmdReportIfspam, msg, headers)
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

// ProcessResponse is the response from the Process and Headers commands.
type ProcessResponse struct {
	// IsSpam reports if this message is considered spam.
	IsSpam bool

	// Score is the spam score of this message.
	Score float64

	// BaseScore is the "minimum spam score" configured on the server. This
	// is usually 5.0.
	BaseScore float64

	// Symbols that matches; only when the Symbols command is used.
	Symbols []string

	// Message headers and body.
	Message io.ReadCloser
}

type rc struct {
	read io.ReadCloser
	buff *bufio.Reader
}

func (r rc) Read(p []byte) (n int, err error) {
	return r.buff.Read(p)
}

func (r rc) Close() error {
	return r.read.Close()
}

// Process this message and return a modified message.
//
// Do not forget to close the Message reader!
func (c *Client) Process(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*ProcessResponse, error) {

	read, err := c.send(ctx, cmdProcess, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	return &ProcessResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
		Message:   rc{read: read, buff: tp.R},
	}, nil
}

// Headers is the same as Process() but returns only modified headers and not
// the body.
//
// Do not forget to close the Message reader!
func (c *Client) Headers(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*ProcessResponse, error) {

	read, err := c.send(ctx, cmdHeaders, msg, headers)
	if err != nil {
		return nil, fmt.Errorf("error sending command to spamd: %v", err)
	}

	respHeaders, tp, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	isSpam, score, baseScore, err := parseSpamHeader(respHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not read Spam header: %v", err)
	}

	return &ProcessResponse{
		IsSpam:    isSpam,
		Score:     score,
		BaseScore: baseScore,
		Message:   rc{read: read, buff: tp.R},
	}, nil
}

// TellResponse is the response of a TELL command.
type TellResponse struct {
	DidSet    []string
	DidRemove []string
}

// Tell what type of we are to process and what should be done with that
// message.
//
// This includes setting or removing a local or a remote database (learning,
// reporting, forgetting, revoking).
//
// Message-class clasifies the message you're sending, and either the Set or
// Remove header specifies which action you want to take.
//
// To learn a message as spam:
//
//     c.Tell(ctx, msg, Header{
//         HeaderMessageClass: MessageClassSpam
//         HeaderSet:          []string{TellLocal},
//     })
//
// Or to learn a message as ham:
//
//     c.Tell(ctx, msg, Header{
//         HeaderMessageClass: MessageClassHam,
//         HeaderSet:          []string{TellLocal},
//     })
func (c *Client) Tell(
	ctx context.Context,
	msg io.Reader,
	headers Header,
) (*TellResponse, error) {

	read, err := c.send(ctx, cmdTell, msg, headers)
	defer read.Close() // nolint: errcheck
	if err != nil {
		if serr, ok := err.(Error); ok && serr.Code == 69 {
			return nil, errors.New(
				"TELL commands are not enabled, set the --allow-tell switch")
		}
		return nil, err
	}

	respHeaders, _, err := readResponse(read)
	if err != nil {
		return nil, fmt.Errorf("could not parse spamd response: %v", err)
	}

	r := &TellResponse{}
	if h, ok := respHeaders[HeaderDidSet]; ok {
		r.DidSet = strings.Split(h, ",")
	}
	if h, ok := respHeaders[HeaderDidRemove]; ok {
		r.DidRemove = strings.Split(h, ",")
	}

	return r, nil
}
