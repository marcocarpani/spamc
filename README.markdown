[![Build Status](https://travis-ci.org/Teamwork/go-spamc.svg?branch=master)](https://travis-ci.org/Teamwork/go-spamc)
[![codecov](https://codecov.io/gh/Teamwork/go-spamc/branch/master/graph/badge.svg?token=n0k8YjbQOL)](https://codecov.io/gh/Teamwork/go-spamc)
[![GoDoc](https://godoc.org/github.com/Teamwork/go-spamc?status.svg)](https://godoc.org/github.com/Teamwork/go-spamc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Teamwork/go-spamc)](https://goreportcard.com/report/github.com/Teamwork/go-spamc)

go-spamc is a Go package to connect to SpamAssassin's spamd daemon.

This is an updated and maintained version of
[saintienn/go-spamc](https://github.com/saintienn/go-spamc), which hasn't been
updated for a few years and has a number of bugs (e.g. panics on certain
messages).

It can:

- Check a message for a spam (du'h).
- Send messages to SpamAssassin to learn.
- Do everything that `spamc` can.

Migrating from saintienn/go-spamc
---------------------------------

This is **not** a drop-in replacement; there are some minor changes:

- `New()` now takes a `time.Duration()` as its timeout, instead of an `int` and
  if it's `0` it will use the default timeout of 20 seconds.

  So add `* time.Second` to convert it to a `time.Duration`.

Example
-------

```go
package main

import (
	"fmt"
	"spamc"
)

func main() {

	html := "<html>Hello world. I'm not a Spam, don't kill me SpamAssassin!</html>"
	client := spamc.New("127.0.0.1:783",10)

	//the 2nd parameter is optional, you can set who (the unix user) do the call
	reply, _ := client.Check(html, "saintienn")

	fmt.Println(reply.Code)
	fmt.Println(reply.Message)
	fmt.Println(reply.Vars)
}
```
