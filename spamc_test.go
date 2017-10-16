package spamc

import (
	"bufio"
	"fmt"
	"net/textproto"
	"reflect"
	"strings"
	"testing"

	"github.com/teamwork/go-spamc/fakeconn"
	"github.com/teamwork/test"
)

func TestWrite(t *testing.T) {
	cases := []struct {
		inCmd, inMsg string
		inHeader     Header
		want         string
		wantErr      string
	}{
		{
			"CMD", "Message", Header{HeaderUser: []string{"xx"}},
			"CMD SPAMC/1.5\r\nContent-length: 9\r\nUser: xx\r\n\r\nMessage\r\n\r\n",
			"",
		},
		{
			"CMD", "Message", nil,
			"CMD SPAMC/1.5\r\nContent-length: 9\r\n\r\nMessage\r\n\r\n",
			"",
		},
		{"", "Message", nil, "", "empty command"},
		{"CMD", "", nil, "CMD SPAMC/1.5\r\nContent-length: 2\r\n\r\n\r\n\r\n", ""},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			conn := fakeconn.New()
			c := Client{conn: conn}

			err := c.write(conn, tc.inCmd, tc.inMsg, tc.inHeader)
			out := conn.Written.String()
			if out != tc.want {
				t.Errorf("wrong data written\nout:  %#v\nwant: %#v\n",
					out, tc.want)
			}
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}

func TestReadResponse(t *testing.T) {
	cases := []struct {
		in             string
		expectedHeader Header
		expectedBody   string
		expectedErr    string
	}{
		{
			in: "SPAMD/1.1 0 EX_OK\r\n" +
				"Header: value\r\n\r\n" +
				"THE BODY",
			expectedHeader: Header{"Header": {"value"}},
			expectedBody:   "THE BODY\r\n",
			expectedErr:    "",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			headers, body, err := readResponse(strings.NewReader(tc.in))

			if !test.ErrorContains(err, tc.expectedErr) {
				t.Errorf("wrong error; want «%v», got «%v»", tc.expectedErr, err)
			}
			if body != tc.expectedBody {
			}
			if !reflect.DeepEqual(headers, tc.expectedHeader) {
				t.Errorf("\nout:      %#v\nexpected: %#v\n", headers, tc.expectedHeader)
			}
		})
	}
}

func TestParseCodeLine(t *testing.T) {
	cases := []struct {
		in       string
		expected string
	}{
		{"SPAMD/1.1 0 EX_OK", ""},
		{"SPAMD/1.1 0", ""},

		{"", "EOF"},
		{"SPAMD/", "short response"},
		{"SPAMD/1.", "short response"},
		{"SPAMD/1.1", "short response"},
		{"SPAMD/1.0 0 EX_OK", "unknown server protocol"},
		{"SPAMD/1.2 0 EX_OK", "unknown server protocol"},
		{"SPAMD/1 0 EX_OK", "unknown server protocol"},
		{"SPAMD/1.1 a EX_OK", "could not parse return code"},
		{"SPAMD/1.1   EX_OK", "could not parse return code"},
		{"SPAMD/1.1 65 EX_OK", "65: Data format error"},
		{"SPAMD/1.1 99 A message", "99: A message"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			out := parseCodeLine(textproto.NewReader(bufio.NewReader(strings.NewReader(tc.in))))
			if !test.ErrorContains(out, tc.expected) {
				t.Errorf("wrong error; want «%v», got «%v»", tc.expected, out)
			}
		})
	}
}
