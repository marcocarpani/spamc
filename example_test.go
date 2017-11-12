package spamc

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

func Example() {
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
}
