// Package spamc is a client library for SpamAssassin's spamd daemon. It
// provides functions for all the commands in the spamd protocol as specified
// here: http://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
//
// All Client functions accept the message as an io.Reader and an optional map
// of Headers (which can be nil).
//
// The Content-length header is mandatory. If the passed io.Reader is an
// strings.Reader, bytes.Reader, or os.File if will be added automatically. For
// other types you'll have to add it yourself:
//
//   conn.Check(ctx, msg, Header{}.Set("Content-length", size))
//
// It is *strongly* recommended that the Header.Set function is used instead of
// directly setting the map. This ensures that the correct capitalisation is
// used; using the Content-Length header is a fatal error ("l" in length needs
// to be lower-case).
package spamc // import "github.com/teamwork/go-spamc"
