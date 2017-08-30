package spamc

import (
	"os"
	"testing"
)

var addr = os.Getenv("SPAMC_SA_ADDRESS") + ":783"

func TestConnect(t *testing.T) {
	client := New(addr, 0)
	r, err := client.Check("x")
	if err != nil {
		t.Fatal(err)
	}

	if r == nil {
		t.Fatal("r is nil")
	}
	if r.Code != ExOK {
		t.Errorf("Code != ExOk: %v", r.Code)
	}
}
