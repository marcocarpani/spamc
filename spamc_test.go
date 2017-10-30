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
	"io"
)

func TestWrite(t *testing.T) {
	cases := []struct {
		inCmd    string
		inMsg    io.ReadSeeker
		inHeader Header
		want     string
		wantErr  string
	}{
		{    // header value (ok) with utf-8
			"CMD", strings.NewReader("Key: ☠Value\r\nMessage"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 26\r\n\r\nKey: ☠Value\r\n\r\nMessage\r\n",
			"",
		},
		{    // header key (bad) with utf-8, will make it a body
			"CMD", strings.NewReader("☠Key: Value\r\nMessage"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 26\r\n\r\n\r\n☠Key: Value\r\nMessage\r\n",
			"",
		},
		{    // correct multiline header
			"CMD", strings.NewReader("Key1: Value1A\r\n\tValue1B\r\nKey2: Value2A\r\n\r\nMessage"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 51\r\n\r\nKey1: Value1A\r\n\tValue1B\r\nKey2: Value2A\r\n\r\nMessage\r\n",
			"",
		},
		{    // bad multiline header
			"CMD", strings.NewReader("Key1: Value1A\r\nValue1B\r\nKey2: Value2A\r\n\r\nMessage"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 52\r\n\r\nKey1: Value1A\r\n\r\nValue1B\r\nKey2: Value2A\r\n\r\nMessage\r\n",
			"",
		},
		{    // bad start of headers
			"CMD", strings.NewReader("\tValue1A\r\nKey2: Value2A\r\n\r\nMessage"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 38\r\n\r\n\r\n\tValue1A\r\nKey2: Value2A\r\n\r\nMessage\r\n",
			"",
		},
		{    // test with wrong Content-length header in something we can read the size of
			"CMD", strings.NewReader("Message"), Header{HeaderContentLength: []string{"15"}},
			"CMD SPAMC/1.5\r\nContent-length: 11\r\n\r\n\r\nMessage\r\n",
			"",
		},
			"CMD", strings.NewReader("Message"), Header{HeaderUser: []string{"xx"}},
			"CMD SPAMC/1.5\r\nContent-length: 11\r\nUser: xx\r\n\r\n\r\nMessage\r\n",
			"",
		},
		{    // test with correctly terminated message
			"CMD", strings.NewReader("Message\r\n"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 11\r\n\r\n\r\nMessage\r\n",
			"",
		},
		{    // test incorrectly terminated message
			"CMD", strings.NewReader("Message"), nil,
			"CMD SPAMC/1.5\r\nContent-length: 11\r\n\r\n\r\nMessage\r\n",
			"",
		},
		{"", strings.NewReader("Message"), nil, "", "empty command"},
		{"CMD", strings.NewReader(""), nil, "CMD SPAMC/1.5\r\nContent-length: 4\r\n\r\n\r\n\r\n", ""},
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
		isPing   bool
	}{
		{"SPAMD/1.1 0 EX_OK", "", false},
		{"SPAMD/1.1 0", "", false},
		{"SPAMD/1.0 0 EX_OK", "", false},

		{"", "EOF", false},
		{"SPAMD/", "short response", false},
		{"SPAMD/1.", "short response", false},
		{"SPAMD/1.1", "short response", false},
		{"SPAMD/1.2 0 EX_OK", "unknown server protocol", false},
		{"SPAMD/1 0 EX_OK", "unknown server protocol", false},
		{"SPAMD/1.1 a EX_OK", "could not parse return code", false},
		{"SPAMD/1.1   EX_OK", "could not parse return code", false},
		{"SPAMD/1.1 65 EX_OK", "65: Data format error", false},
		{"SPAMD/1.1 99 A message", "99: A message", false},

		{"SPAMD/1.5 0 PONG", "", true},
		{"SPAMD/1.1 0 PONG", "unexpected", true},
		{"SPAMD/1.5 65 PONG", "code 65", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			out := parseCodeLine(textproto.NewReader(bufio.NewReader(strings.NewReader(tc.in))), tc.isPing)
			if !test.ErrorContains(out, tc.expected) {
				t.Errorf("wrong error; want «%v», got «%v»", tc.expected, out)
			}
		})
	}
}

func TestParseSpamHeader(t *testing.T) {
	cases := []struct {
		in                       Header
		wantIsSpam               bool
		wantScore, wantBaseScore float64
		wantErr                  string
	}{
		// Invalid data
		{Header{}, false, 0, 0, "header missing"},
		{Header{"Spam": []string{""}}, false, 0, 0, "header empty"},
		{
			Header{"Spam": []string{"clearly incorrect"}},
			false, 0, 0, "unexpected data",
		},
		{
			Header{"Spam": []string{"bacon ; 0 / 0"}},
			false, 0, 0, "unknown spam status",
		},
		{
			Header{"Spam": []string{"no ; 0 "}},
			false, 0, 0, "unexpected data",
		},
		{
			Header{"Spam": []string{"no ; 0 / "}},
			false, 0, 0, "could not parse",
		},
		{
			Header{"Spam": []string{"no ; 0 / asd"}},
			false, 0, 0, "could not parse",
		},
		{
			Header{"Spam": []string{"no ; asd / 0"}},
			false, 0, 0, "could not parse",
		},

		// Valid data
		{
			Header{"Spam": []string{"no ; 0.1 / 5.0"}},
			false, .1, 5.0, "",
		},
		{
			Header{"Spam": []string{"no;0.1 / 5.0"}},
			false, .1, 5.0, "",
		},
		{
			Header{"Spam": []string{"no;0.1/5.0"}},
			false, .1, 5.0, "",
		},
		{
			Header{"Spam": []string{"no;-0.1/5.0"}},
			false, -.1, 5.0, "",
		},
		{
			Header{"Spam": []string{"TRUe ; 4 / 7.0"}},
			true, 4.0, 7.0, "",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			isSpam, score, baseScore, err := parseSpamHeader(tc.in)

			if isSpam != tc.wantIsSpam {
				t.Errorf("isSpam wrong\nout:  %#v\nwant: %#v\n",
					isSpam, tc.wantIsSpam)
			}
			if score != tc.wantScore {
				t.Errorf("score wrong\nout:  %#v\nwant: %#v\n",
					score, tc.wantScore)
			}
			if baseScore != tc.wantBaseScore {
				t.Errorf("baseScore wrong\nout:  %#v\nwant: %#v\n",
					baseScore, tc.wantBaseScore)
			}
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("error wrong\nout:  %#v\nwant: %#v\n",
					err, tc.wantErr)
			}
		})
	}
}
