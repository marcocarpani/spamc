package spamc

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/teamwork/go-spamc/fakeconn"
	"github.com/teamwork/test"
)

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

			out, err := c.Check(context.Background(), "A message", nil)
			if !test.ErrorContains(err, tc.wantErr) {
				t.Errorf("wrong error\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
			if !reflect.DeepEqual(out, tc.want) {
				t.Errorf("\nout:  %#v\nwant: %#v\n", out, tc.want)
			}
		})
	}
}
