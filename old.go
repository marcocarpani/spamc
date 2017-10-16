package spamc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

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
	show := false
	data := bufio.NewReader(read)
	defer data.UnreadByte() // nolint: errcheck

	// Read the first line.
	line, _, _ := data.ReadLine()
	lineStr := string(line)
	if show {
		fmt.Println(lineStr)
	}

	var result = reParseResponse.FindStringSubmatch(lineStr)
	if len(result) < 4 {
		if cmd != "SKIP" {
			return nil, fmt.Errorf("spamd unrecognised reply: %v", lineStr)
		}
		return &Response{
			Message: "SKIPPED",
		}, nil
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
			if show {
				fmt.Println(string(line))
			}

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
	if show {
		fmt.Println(string(line))
	}

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

	case CmdReport,
		CmdReportIfspam,
		CmdProcess,
		CmdHeaders:

		// ignore content-length header..
		line, _, err = data.ReadLine()
		if show {
			fmt.Println(string(line))
		}
		lineStr = string(line)

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
				if show {
					fmt.Println(string(line))
				}
				if err == io.EOF || err != nil {
					if err == io.EOF {
						err = nil
					}
					return returnObj, err
				}
				lines += string(line) + "\r\n"
				returnObj.Vars["body"] = lines
			}

		case CmdReport, CmdReportIfspam:
			// ignore line break...
			_, _, err := data.ReadLine()
			if show {
				fmt.Println(string(line))
			}
			if err != nil {
				return nil, err
			}

			for {
				line, _, err = data.ReadLine()
				if show {
					fmt.Println(string(line))
				}

				if len(line) > 0 {
					lineStr = string(line)

					// TXT Table found, prepare to parse..
					if len(lineStr) >= 4 && lineStr[0:4] == tableMark {

						section := []map[string]interface{}{}
						tt := 0
						for {
							line, _, err = data.ReadLine()
							if show {
								fmt.Println(string(line))
							}
							// Stop read the text table if last line or Void line
							if err == io.EOF || err != nil || len(line) == 0 {
								if err == io.EOF {
									err = nil // nolint: ineffassign
								}
								break
							}
							// Parsing
							lineStr = string(line)
							spc := 2
							if lineStr[0:1] == "-" {
								spc = 1
							}
							lineStr = strings.Replace(lineStr, " ", split, spc)
							lineStr = strings.Replace(lineStr, " ", split, 1)
							if spc > 1 {
								lineStr = " " + lineStr[2:]
							}
							x := strings.Split(lineStr, split)
							if lineStr[1:3] == split {
								section[tt-1]["message"] = fmt.Sprintf("%v %v", section[tt-1]["message"], strings.TrimSpace(lineStr[5:]))
							} else {
								if len(x) != 0 {
									message := strings.TrimSpace(x[2])
									score, _ := strconv.ParseFloat(strings.TrimSpace(x[0]), 64)

									section = append(section, map[string]interface{}{
										"score":   score,
										"symbol":  x[1],
										"message": message,
									})

									tt++
								}
							}
						}

						returnObj.Vars["report"] = section
						break
					}
				}

				if err == io.EOF || err != nil {
					if err == io.EOF {
						err = nil // nolint: ineffassign
					}
					break
				}
			}
		}
	}

	if err != io.EOF {
		for {
			line, _, err = data.ReadLine() // nolint: ineffassign
			if show {
				fmt.Println(string(line))
			}
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
