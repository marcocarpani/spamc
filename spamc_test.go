package spamc

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/teamwork/test"
)

type tconn struct {
	data []byte
}

var data []byte

func (c tconn) Write(b []byte) (n int, err error) {
	c.data = append(c.data, b...)
	data = append(data, b...)
	return 0, nil
}

func (c tconn) Read(b []byte) (n int, err error)   { return 0, nil }
func (c tconn) Close() error                       { return nil }
func (c tconn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c tconn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c tconn) SetDeadline(t time.Time) error      { return nil }
func (c tconn) SetReadDeadline(t time.Time) error  { return nil }
func (c tconn) SetWriteDeadline(t time.Time) error { return nil }

func TestWrite(t *testing.T) {
	conn := tconn{}
	client := Client{}
	err := client.write(conn, "CMD", "The message", "user", nil)
	if err != nil {
		t.Fatal(err)
	}

	out := string(data)
	expected := "SPAMC/1.5\r\nContent-Length: 13\r\n\r\nThe message\r\n"

	if out != expected {
		t.Errorf("\nout:      %#v\nexpected: %#v\n", out, expected)
	}

	/*
		cases := []struct {
		}{
			{},
		}

		for i, tc := range cases {
			//t.Run(fmt.Sprintf("%v", tc.in), func(t *testing.T) {
			t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
				//out := ...
				if out != tc.expected {
					t.Errorf("\nout:      %#v\nexpected: %#v\n", out, tc.expected)
				}

				//if !reflect.DeepEqual(tc.expected, out) {
				//	t.Errorf("\nout:      %#v\nexpected: %#v\n", out, tc.expected)
				//}
				//if diff.Diff(tc.expected, out) != "" {
				//	t.Errorf(diff.Cmp(tc.expected, out))
				//}
			})
		}
	*/
}

func TestReadResponse(t *testing.T) {
	cases := []struct {
		in             string
		expectedHeader textproto.MIMEHeader
		expectedBody   string
		expectedErr    string
	}{
		{
			in: "SPAMD/1.1 0 EX_OK\r\n" +
				"Header: value\r\n\r\n" +
				"THE BODY",
			expectedHeader: textproto.MIMEHeader{"Header": {"value"}},
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
