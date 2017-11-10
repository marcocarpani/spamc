package spamc

// Header key constants.
const (
	HeaderContentLength = "Content-length"
	HeaderMessageClass  = "Message-class"
	HeaderRemove        = "Remove"
	HeaderSet           = "Set"
	HeaderSpam          = "Spam"
	HeaderUser          = "User"
)

var allHeaders = []string{HeaderContentLength, HeaderMessageClass,
	HeaderRemove, HeaderSet, HeaderSpam, HeaderUser}

// Header for requests.
type Header map[string]string
