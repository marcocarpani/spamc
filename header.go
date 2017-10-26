package spamc

import "net/textproto"

// Header key constants.
const (
	HeaderContentLength = "Content-length"
	HeaderUser          = "User"
	HeaderMessageClass  = "Message-class"
	HeaderSet           = "Set"
	HeaderRemove        = "Remove"
)

// Header for requests.
type Header map[string][]string

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
func (h Header) Add(key, value string) {
	key = textproto.CanonicalMIMEHeaderKey(key)
	h[key] = append(h[key], value)
}

// Set sets the header entries associated with key to
// the single element value. It replaces any existing
// values associated with key.
func (h Header) Set(key, value string) {
	h[textproto.CanonicalMIMEHeaderKey(key)] = []string{value}
}

// Get gets the first value associated with the given key.
// It is case insensitive; CanonicalMIMEHeaderKey is used
// to canonicalize the provided key.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, or to use non-canonical keys,
// access the map directly.
func (h Header) Get(key string) string {
	if h == nil {
		return ""
	}
	v := h[textproto.CanonicalMIMEHeaderKey(key)]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Del deletes the values associated with key.
func (h Header) Del(key string) {
	delete(h, textproto.CanonicalMIMEHeaderKey(key))
}
