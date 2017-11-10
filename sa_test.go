// +build testsa

package spamc

import (
	"context"
	"fmt"
	"os"
	"testing"
)

var addr = os.Getenv("SPAMC_SA_ADDRESS") + ":783"

func TestSAPing(t *testing.T) {
	client := New(addr, 0)
	err := client.Ping(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestSATell(t *testing.T) {
	client := New(addr, 0)
	message := "Subject: Hello, world!\r\n\r\nTest message.\r\n"
	r, err := client.Tell(context.Background(), message, Header{
		"Message-class": []string{"spam"},
		"Set":           []string{"local"},
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
	message := "Subject: Hello, world!\r\n\r\nTest message.\r\n"
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

	r, err := client.Check(context.Background(), "woot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}

	r, err = client.Check(context.Background(), "Subject: woot\r\n\r\nwoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSACheck(t *testing.T) {
	client := New(addr, 0)
	r, err := client.Check(context.Background(), "\r\nPenis viagra\r\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSASymbols(t *testing.T) {
	client := New(addr, 0)
	r, err := client.Symbols(context.Background(), ""+
		"Date: now\r\n"+
		"From: a@example.com\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body\r\n"+
		"", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}
}

func TestSAReport(t *testing.T) {
	client := New(addr, 0)
	r, err := client.Report(context.Background(), ""+
		"Date: now\r\n"+
		"From: a@example.com\r\n"+
		"Subject: Hello\r\n"+
		"Message-ID: <serverfoo2131645635@example.com>\r\n"+
		"\r\n\r\nthe body"+
		"", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("r is nil")
	}

	fmt.Printf("%#v\n", r)
}
