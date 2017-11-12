[![Build Status](https://travis-ci.org/Teamwork/spamc.svg?branch=master)](https://travis-ci.org/Teamwork/spamc)
[![codecov](https://codecov.io/gh/Teamwork/spamc/branch/master/graph/badge.svg?token=n0k8YjbQOL)](https://codecov.io/gh/Teamwork/spamc)
[![GoDoc](https://godoc.org/github.com/Teamwork/spamc?status.svg)](https://godoc.org/github.com/Teamwork/spamc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Teamwork/spamc)](https://goreportcard.com/report/github.com/Teamwork/spamc)

spamc is a Go client library for SpamAssassin's spamd daemon.

It started out as a fork of saintienn/go-spamc with some fixes, but has since
been completely rewritten.

Basic example:

	// Connect
	c := New("127.0.0.1:783", &net.Dialer{
		Timeout: 20 * time.Second,
	})
	ctx := context.Background()

	// Check if a message is spam.
	report, err := c.Check(ctx, strings.NewReader("Hello"), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(report.Score)

	// Report ham for training.
	c.Tell(ctx, msg, Header{}.
		Set("Message-class", "ham").
		Set("Set", "local"))

See godoc for the full documentation.

Runnings tests
--------------

Use `./bin/test` to run all tests; use `./bin/test -b testsa` to run tests that
require a running SpamAssassin instance. This will automatically run SA in a
Docker container. You can also use the `SPAMC_SA_ADDRESS` to set the SA address.
