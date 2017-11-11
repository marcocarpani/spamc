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

This is **not** a drop-in replacement; there are a bunch of changes to the API.
See godoc. The API is **not** yet stable!

The biggest caveat is that `New()` now takes a `time.Duration()` as its timeout,
instead of an `int` and if it's `0` it will use the default timeout of 20
seconds. So add `* time.Second` to convert it to a `time.Duration`.

Runnings tests
--------------

Use `./bin/test` to run all tests; use `./bin/test -b testsa` to run tests that
require a running SpamAssassin instance. This will automatically run SA in a
Docker container.
You can also use the `SPAMC_SA_ADDRESS` to indicate the SA address.
