package spamc

// All of

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Response is the default response struct.
type Response struct {
	Message string
	Vars    map[string]interface{}
}

// wrapper to simple calls.
func (c *Client) simpleCall(
	cmd, msg string,
	headers Header,
) (*Response, error) {

	read, err := c.send(context.TODO(), cmd, msg, headers)
	defer read.Close() // nolint: errcheck
	if err != nil {
		return nil, err
	}

	return processResponse(cmd, read)
}

var (
	reParseResponse = regexp.MustCompile(`(?i)SPAMD\/([0-9\.\-]+)\s([0-9]+)\s([0-9A-Z_]+)`)
	reFindScore     = regexp.MustCompile(`(?i)Spam:\s(True|False|Yes|No)\s;\s(-?[0-9\.]+)\s\/\s(-?[0-9\.]+)`)
)

// Spamd reply processor.
func processResponse(cmd string, read io.Reader) (*Response, error) {
	data := bufio.NewReader(read)
	defer data.UnreadByte() // nolint: errcheck

	// Read the first line.
	line, _, _ := data.ReadLine()
	lineStr := string(line)

	var result = reParseResponse.FindStringSubmatch(lineStr)
	if len(result) < 4 {
		return nil, fmt.Errorf("spamd unrecognised reply: %v", lineStr)
	}

	returnCode, err := strconv.Atoi(result[2])
	if err != nil {
		return nil, fmt.Errorf("could not read spamd code: %v", err)
	}

	returnObj := &Response{
		Message: result[3],
		Vars:    make(map[string]interface{}),
	}

	// spamd returned code != 0
	if returnCode > 0 {
		if errorMessages[returnCode] != "" {
			err = fmt.Errorf("spamd code %v: %v",
				returnCode, errorMessages[returnCode])
		} else {
			err = fmt.Errorf("spamd code %v (unknown)", returnCode)
		}
		returnObj.Vars["error_description"] = errorMessages[returnCode]
		return returnObj, err
	}

	// start didSet
	if cmd == CmdTell {
		returnObj.Vars["didSet"] = false
		returnObj.Vars["didRemove"] = false
		for {
			line, _, err = data.ReadLine()

			if err == io.EOF || err != nil {
				if err == io.EOF {
					err = nil
				}
				break
			}
			if strings.Contains(string(line), "DidRemove") {
				returnObj.Vars["didRemove"] = true
			}
			if strings.Contains(string(line), "DidSet") {
				returnObj.Vars["didSet"] = true
			}

		}
		return returnObj, err
	}
	// read the second line
	line, _, err = data.ReadLine()

	// finish here if line is empty
	if len(line) == 0 {
		if err == io.EOF {
			err = nil
		}
		return returnObj, err
	}

	// ignore content-length header..
	lineStr = string(line)
	switch cmd {

	case CmdProcess,
		CmdHeaders:

		// ignore content-length header..
		_, _, err = data.ReadLine()

		var result = reFindScore.FindStringSubmatch(lineStr)

		if len(result) > 0 {
			returnObj.Vars["isSpam"] = false
			switch result[1][0:1] {
			case "T", "t", "Y", "y":
				returnObj.Vars["isSpam"] = true
			}
			returnObj.Vars["spamScore"], _ = strconv.ParseFloat(result[2], 64)
			returnObj.Vars["baseSpamScore"], _ = strconv.ParseFloat(result[3], 64)
		}

		switch cmd {
		case CmdProcess, CmdHeaders:
			lines := ""
			for {
				line, _, err = data.ReadLine()
				if err == io.EOF || err != nil {
					if err == io.EOF {
						err = nil
					}
					return returnObj, err
				}
				lines += string(line) + "\r\n"
				returnObj.Vars["body"] = lines
			}

		}
	}

	if err != io.EOF {
		for {
			line, _, err = data.ReadLine() // nolint: ineffassign
			if err == io.EOF || err != nil {
				if err == io.EOF {
					err = nil
				}
				break
			}
		}
	}
	return returnObj, err
}
