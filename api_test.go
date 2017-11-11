package spamc

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/teamwork/test"
	"github.com/teamwork/test/fakeconn"
)

func TestPing(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"SPAMD/1.5 0 PONG\r\n", ""},
		{"SPAMD/1.5 1 error\r\n", "spamd returned code 1"},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			conn := fakeconn.New()
			conn.ReadFrom.WriteString(tc.in)
			c := Client{conn: conn}
			testConnHook = conn
			defer func() { testConnHook = nil }()

			err := c.Ping(context.Background())
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		in      string
		want    *CheckResponse
		wantErr string
	}{
		{
			"SPAMD/1.1 0 EX_OK\r\nSpam: yes; 6.42 / 5.0\r\n\r\n",
			&CheckResponse{
				IsSpam:    true,
				Score:     6.42,
				BaseScore: 5,
			},
			"",
		},
		{
			"SPAMD/1.1 0 EX_OK\r\nSpam: no; -2.0 / 5.0\r\n\r\n",
			&CheckResponse{
				IsSpam:    false,
				Score:     -2.0,
				BaseScore: 5,
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			conn := fakeconn.New()
			conn.ReadFrom.WriteString(tc.in)
			c := Client{conn: conn}
			testConnHook = conn
			defer func() { testConnHook = nil }()

			out, err := c.Check(context.Background(), strings.NewReader("A message"), nil)
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

func TestSymbols(t *testing.T) {
	cases := []struct {
		in      string
		want    *CheckResponse
		wantErr string
	}{
		{
			"SPAMD/1.1 0 EX_OK\r\n" +
				"Content-length: 50\r\n" +
				"Spam: False ; 1.6 / 5.0\r\n" +
				"\r\n" +
				"INVALID_DATE,MISSING_HEADERS,NO_RECEIVED,NO_RELAYS\r\n",
			&CheckResponse{
				IsSpam:    false,
				Score:     1.6,
				BaseScore: 5.0,
				Symbols:   []string{"INVALID_DATE", "MISSING_HEADERS", "NO_RECEIVED", "NO_RELAYS"},
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			conn := fakeconn.New()
			conn.ReadFrom.WriteString(tc.in)
			c := Client{conn: conn}
			testConnHook = conn
			defer func() { testConnHook = nil }()

			out, err := c.Symbols(context.Background(), strings.NewReader("A message"), nil)
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

/*
func TestReport(t *testing.T) {
	cases := []struct {
		in      string
		want    *ReportResponse
		wantErr string
	}{
		{
			"SPAMD/1.1 0 EX_OK\r\n" +
				"Content-length: 50\r\n" +
				"Spam: False ; 1.6 / 5.0\r\n" +
				"\r\n" +
				"INVALID_DATE,MISSING_HEADERS,NO_RECEIVED,NO_RELAYS\r\n",
			&ReportResponse{
				IsSpam:    false,
				Score:     1.6,
				BaseScore: 5.0,
				//Report:   []string{"INVALID_DATE", "MISSING_HEADERS", "NO_RECEIVED", "NO_RELAYS"},
			},
			"",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			conn := fakeconn.New()
			conn.ReadFrom.WriteString(tc.in)
			c := Client{conn: conn}
			testConnHook = conn
			defer func() { testConnHook = nil }()

			out, err := c.Report(context.Background(), strings.NewReader("A message"), nil)
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", err, tc.wantErr)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}
*/
