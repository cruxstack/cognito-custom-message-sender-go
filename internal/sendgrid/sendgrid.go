// Package sendgrid is a minimal client for the two SendGrid v3 APIs this
// service uses: Mail Send with dynamic templates, and Email Address
// Validation.
package sendgrid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

// DefaultBaseURL is the global SendGrid API host. Accounts with EU data
// residency use https://api.eu.sendgrid.com.
const DefaultBaseURL = "https://api.sendgrid.com"

const (
	pathMailSend      = "/v3/mail/send"
	pathValidateEmail = "/v3/validations/email"

	// maxErrorBody bounds how much of an error response is kept
	maxErrorBody = 4 << 10
)

// Client calls the SendGrid API with one API key.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New returns a client for baseURL (DefaultBaseURL when empty). A nil
// httpClient uses a client with a 10 second timeout.
func New(baseURL, apiKey string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: httpClient}
}

// APIError is a non-2xx response from the SendGrid API.
type APIError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sendgrid %s returned status %d: %s", e.Path, e.StatusCode, e.Body)
}

// TemplateEmail is a message rendered from a SendGrid dynamic template.
type TemplateEmail struct {
	// From is an address, optionally with a display name ("ACME <a@b.c>").
	From       string
	To         string
	TemplateID string
	Data       map[string]any
}

// SendTemplate sends one dynamic template email.
func (c *Client) SendTemplate(ctx context.Context, m TemplateEmail) error {
	type address struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
	}
	type personalization struct {
		To   []address      `json:"to"`
		Data map[string]any `json:"dynamic_template_data,omitempty"`
	}
	body := struct {
		From             address           `json:"from"`
		TemplateID       string            `json:"template_id"`
		Personalizations []personalization `json:"personalizations"`
	}{
		TemplateID:       m.TemplateID,
		Personalizations: []personalization{{Data: m.Data}},
	}

	fromName, fromAddr := splitAddress(m.From)
	body.From = address{Email: fromAddr, Name: fromName}
	_, toAddr := splitAddress(m.To)
	body.Personalizations[0].To = []address{{Email: toAddr}}

	_, err := c.post(ctx, pathMailSend, body)
	return err
}

// Validation is the result of validating one email address.
type Validation struct {
	Email   string  `json:"email"`
	Verdict string  `json:"verdict"`
	Score   float64 `json:"score"`
	Checks  struct {
		Domain struct {
			HasValidAddressSyntax        bool `json:"has_valid_address_syntax"`
			HasMXOrARecord               bool `json:"has_mx_or_a_record"`
			IsSuspectedDisposableAddress bool `json:"is_suspected_disposable_address"`
		} `json:"domain"`
		LocalPart struct {
			IsSuspectedRoleAddress bool `json:"is_suspected_role_address"`
		} `json:"local_part"`
		Additional struct {
			HasKnownBounces     bool `json:"has_known_bounces"`
			HasSuspectedBounces bool `json:"has_suspected_bounces"`
		} `json:"additional"`
	} `json:"checks"`
}

// Verdicts returned by the Email Address Validation API.
const (
	VerdictValid   = "Valid"
	VerdictRisky   = "Risky"
	VerdictInvalid = "Invalid"
)

// ValidateEmail validates one address. It returns the parsed result and the
// raw response body.
func (c *Client) ValidateEmail(ctx context.Context, email string) (*Validation, []byte, error) {
	raw, err := c.post(ctx, pathValidateEmail, map[string]string{"email": email, "source": "cognito"})
	if err != nil {
		return nil, nil, err
	}

	var resp struct {
		Result Validation `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, raw, fmt.Errorf("decode sendgrid validation response: %w", err)
	}
	return &resp.Result, raw, nil
}

func (c *Client) post(ctx context.Context, path string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode sendgrid request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build sendgrid request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sendgrid %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, &APIError{Path: path, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read sendgrid %s response: %w", path, err)
	}
	return b, nil
}

// splitAddress splits "Name <addr>" into its parts. A value that doesn't
// parse is returned as the address.
func splitAddress(s string) (name, addr string) {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", strings.TrimSpace(s)
	}
	return a.Name, a.Address
}
