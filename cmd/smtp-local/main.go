package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mhale/smtpd"
)

type EmailJSON struct {
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Subject     string            `json:"subject"`
	Date        string            `json:"date"`
	MessageID   string            `json:"message_id"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	BodyPreview string            `json:"body_preview"`
	SizeBytes   int               `json:"size_bytes"`
	Filename    string            `json:"filename"`
	RawBase64   string            `json:"raw_b64"`
	SHA256Hex   string            `json:"sha256_hex"`
}

var (
	listenPort           string
	mailDir              string
	webhookURL           string
	webhookTimeout       time.Duration
	authRequired         bool
	authUser             string
	authPass             string
	insecurePlainAllowed bool // advertise PLAIN/LOGIN without TLS (local/testing)
)

func init() {
	flag.StringVar(&listenPort, "listen-port", "2525", "TCP port listen on, e.g. 2525")
	flag.StringVar(&mailDir, "mail-dir", "/tmp/mail", "Directory to store incoming .eml files")
	flag.StringVar(&webhookURL, "webhook-url", "", "If set, send each received email as JSON to this webhook via POST")
	flag.DurationVar(&webhookTimeout, "webhook-timeout", 5*time.Second, "HTTP timeout for webhook POST")

	flag.BoolVar(&authRequired, "auth-required", false, "Require SMTP AUTH before accepting MAIL/RCPT")
	flag.StringVar(&authUser, "auth-user", "", "Static username for AUTH (empty means any username is accepted if password matches)")
	flag.StringVar(&authPass, "auth-pass", "", "Static password for AUTH")
	flag.BoolVar(&insecurePlainAllowed, "auth-allow-insecure-plain", true, "Advertise PLAIN/LOGIN even without TLS (local/testing only)")

	flag.Parse()

	if err := os.MkdirAll(mailDir, 0o755); err != nil {
		log.Fatalf("failed to create maildir: %v\n", err)
	}
}

func main() {
	log.Printf("saved emails directory: %s\n", mailDir)
	log.Printf("webhook url: %s\n", webhookURL)
	log.Printf("webhook timeout: %s\n", webhookTimeout)
	handler := func(origin net.Addr, from string, to []string, data []byte) error {
		tstamp := time.Now().Format("2006-01-02-15:04:05.000000000Z07")
		safeFrom := sanitizeFilename(strings.Trim(from, "<>"))
		filename := filepath.Join(mailDir, fmt.Sprintf("%s_%s_%d.eml", tstamp, safeFrom, os.Getpid()))
		if err := os.WriteFile(filename, data, 0o644); err != nil {
			return fmt.Errorf("save email: %w", err)
		}

		emailJSON := buildEmailJSON(from, to, data, filename)

		log.Printf("Received mail from=%q to=%q subject=%q saved=%q size=%dB",
			emailJSON.From, strings.Join(emailJSON.To, ", "),
			emailJSON.Subject, emailJSON.Filename, emailJSON.SizeBytes)

		if webhookURL != "" {
			client := &http.Client{Timeout: webhookTimeout}
			defer client.CloseIdleConnections()
			if err := postToWebhook(client, webhookURL, emailJSON); err != nil {
				log.Printf("webhook POST failed: %v", err)
			} else {
				log.Printf("webhook POST ok → %s", webhookURL)
			}
		}
		return nil
	}

	var authHandler smtpd.AuthHandler
	if authRequired || authUser != "" || authPass != "" || insecurePlainAllowed {
		authHandler = func(_ net.Addr, mechanism string, username, password, _ []byte) (bool, error) {
			u := string(username)
			p := string(password)

			// static checks; replace with DB/LDAP/etc if needed
			if authUser != "" && u != authUser {
				return false, nil
			}
			if authPass != "" && p != authPass {
				return false, nil
			}
			// if no specific creds provided, accept any (for local dev)
			return true, nil
		}
	}

	var mechs map[string]bool
	if insecurePlainAllowed {
		mechs = map[string]bool{"PLAIN": true, "LOGIN": true}
	}
	srv := &smtpd.Server{
		Addr:         ":" + listenPort,
		Hostname:     "localhost",
		Appname:      "SMTP Server",
		Handler:      handler,
		AuthHandler:  authHandler,
		AuthMechs:    mechs,        // nil = package defaults; here we force PLAIN/LOGIN
		AuthRequired: authRequired, // if true, require AUTH before MAIL/RCPT
	}

	log.Printf("Starting SMTP server on %s (host=%s, authRequired=%v, insecurePlain=%v)",
		srv.Addr, srv.Hostname, authRequired, insecurePlainAllowed)

	if err := srv.ListenAndServe(); err != nil {
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

func postToWebhook(client *http.Client, url string, payload EmailJSON) error {
	blob, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("non-2xx status: %s, body: %s", resp.Status, string(body))
	}
	return nil
}

func buildEmailJSON(from string, to []string, data []byte, filename string) EmailJSON {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	var (
		subject   string
		dateHdr   string
		messageID string
		headers   = map[string]string{}
		bodyText  string
	)
	if err == nil && msg != nil {
		for k, v := range msg.Header {
			if len(v) > 0 {
				headers[k] = strings.Join(v, ", ")
			}
		}
		subject = decodeRFC2047(headers["Subject"])
		dateHdr = headers["Date"]
		messageID = headers["Message-ID"]

		rawBody, _ := io.ReadAll(msg.Body)
		bodyText = decodeBody(msg.Header, rawBody)
	} else {
		bodyText = ""
	}

	sum := sha256.Sum256(data)
	rawB64 := base64.StdEncoding.EncodeToString(data)

	preview := bodyText
	if len(preview) > 200 {
		preview = preview[:200]
	}

	return EmailJSON{
		From:        from,
		To:          to,
		Subject:     subject,
		Date:        dateHdr,
		MessageID:   messageID,
		Headers:     headers,
		Body:        bodyText,
		BodyPreview: preview,
		SizeBytes:   len(data),
		Filename:    filename,
		RawBase64:   rawB64,
		SHA256Hex:   fmt.Sprintf("%x", sum[:]),
	}
}

func decodeRFC2047(s string) string {
	if s == "" {
		return s
	}
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

func decodeBody(h mail.Header, raw []byte) string {
	cte := strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding")))
	if cte == "quoted-printable" {
		qr := quotedprintable.NewReader(bytes.NewReader(raw))
		b, err := io.ReadAll(qr)
		if err == nil {
			raw = b
		}
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return text
}
