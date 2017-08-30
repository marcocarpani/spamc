go-spamc is a Go package to connect to SpamAssassin's spamd daemon.

This is an updated and maintained version of
[saintienn/go-spamc](https://github.com/saintienn/go-spamc), which hasn't been
updated for a few years and has a number of bugs (e.g. panics on certain
messages).

It can:

- Check a message for a spam (du'h).
- Send messages to SpamAssassin to learn.
- Do everything that `spamc` can.

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
