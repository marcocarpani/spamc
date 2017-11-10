// +build testsa

package spamc

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

var addr = os.Getenv("SPAMC_SA_ADDRESS") + ":783"

// Basic test to confirm that the commands return *something* until we have more
// robust test in place.
func TestSACommands(t *testing.T) {
	client := New(addr, 0)
	message := "Subject: Hello, world!\r\n\r\nTest message.\r\n"

	cases := []struct {
		name string
		fun  func(context.Context, io.ReadSeeker, Header) (*Response, error)
	}{
		//{"Check", client.Check},
		//{"Symbols", client.Symbols},
		{"Report", client.Report},
		{"ReportIfSpam", client.ReportIfSpam},
		{"Process", client.Process},
		{"Header", client.Headers},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%v", tc.name), func(t *testing.T) {
			r, err := tc.fun(context.Background(), strings.NewReader(message), nil)
			if err != nil {
				t.Fatalf("error: %v\nmessage: %#v", err, message)
			}
			if r == nil {
				t.Fatal("r is nil")
			}
		})
	}
}

func TestSAPing(t *testing.T) {
	client := New(addr, 0)
	err := client.Ping(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestSATell(t *testing.T) {
	client := New(addr, 0)
	message := strings.NewReader("Subject: Hello, world!\r\n\r\nTest message.\r\n")
	r, err := client.Tell(context.Background(), message, Header{
		"Message-class": "spam",
		"Set":           "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSALearn(t *testing.T) {
	client := New(addr, 0)
	message := strings.NewReader("Subject: Hello, world!\r\n\r\nTest message.\r\n")
	r, err := client.Learn(context.Background(), LearnHam, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSANoTrailingNewline(t *testing.T) {
	client := New(addr, 0)

	r, err := client.Check(context.Background(), strings.NewReader("woot"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}

	r, err = client.Check(context.Background(), strings.NewReader("Subject: woot\r\n\r\nwoot"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSACheck(t *testing.T) {
	client := New(addr, 0)
	r, err := client.Check(context.Background(), strings.NewReader("\r\nPenis viagra\r\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSASymbols(t *testing.T) {
	client := New(addr, 0)
	r, err := client.Symbols(context.Background(), strings.NewReader(""+
		"Date: now\r\n"+
		"From: a@example.com\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body\r\n"+
		""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}
