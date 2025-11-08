package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mhale/smtpd"
)

var listenPort string
var mailDir string

func init() {
	listenPort = os.Getenv("LISTEN_PORT")
	if listenPort == "" {
		listenPort = "2525"
	}
	mailDir = os.Getenv("MAIL_DIR")
	if mailDir == "" {
		mailDir = "/tmp/mail"
	}
}

func main() {
	if err := os.MkdirAll(mailDir, 0o755); err != nil {
		log.Fatalf("failed to create maildir: %v", err)
	}

	handler := func(origin net.Addr, from string, to []string, data []byte) error {
		tstamp := time.Now().Format("2006-01-02-15:04:05.000000000")
		safeFrom := strings.ReplaceAll(strings.ReplaceAll(from, "<", ""), ">", "")
		base := fmt.Sprintf("%s_%s_%d.eml", tstamp, sanitizeFilename(safeFrom), os.Getpid())
		path := filepath.Join(mailDir, base)

		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("save email: %w", err)
		}

		subject := parseHeader(data, "Subject")
		log.Printf("Received: from=%q to=%q subject=%q saved=%s", from, strings.Join(to, ", "), subject, path)
		return nil
	}

	log.Printf("Starting SMTP server on :%s (no TLS, no auth)", listenPort)
	if err := smtpd.ListenAndServe(":"+listenPort, handler, "SMTP Server", ""); err != nil {
		log.Fatal(err)
	}
}

// sanitizeFilename keeps filenames safe/cross-platform.
func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_",
		"\"", "_", "<", "_", ">", "_", "|", "_", " ", "_",
	)
	return replacer.Replace(s)
}

// parseHeader extracts a single header value from raw message.
func parseHeader(data []byte, header string) string {
	h := header + ":"
	r := strings.NewReader(string(data))
	for {
		line, err := readLine(r)
		if err != nil {
			return ""
		}
		if line == "" { // end of headers
			return ""
		}
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(h)) {
			return strings.TrimSpace(line[len(h):])
		}
	}
}

// readLine reads up to CRLF.
func readLine(r *strings.Reader) (string, error) {
	var b strings.Builder
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			if b.Len() == 0 {
				return "", err
			}
			return b.String(), nil
		}
		if ch == '\r' {
			// look ahead for '\n'
			n, _, err2 := r.ReadRune()
			if err2 == nil && n == '\n' {
				return b.String(), nil
			}
			// if not '\n', push back
			if err2 == nil {
				r.UnreadRune()
			}
			return b.String(), nil
		}
		if ch == '\n' {
			return b.String(), nil
		}
		b.WriteRune(ch)
	}
}
