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
			"CMD SPAMC/1.5\r\nContent-length: 9\r\nUser: xx\r\n\r\nMessage\r\n",
			"",
		},
		{
			"CMD", "Message", nil,
			"CMD SPAMC/1.5\r\nContent-length: 9\r\n\r\nMessage\r\n",
			"",
		},
		{"", "Message", nil, "", "empty command"},
		{"CMD", "", nil, "CMD SPAMC/1.5\r\nContent-length: 2\r\n\r\n\r\n", ""},
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
