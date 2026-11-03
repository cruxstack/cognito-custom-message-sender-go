package verify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sendgrid"
)

func TestOffline(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name+tag@sub.example.co.uk",
		"a@b.co",
		"ACME <user@example.com>",
	}
	for _, email := range valid {
		r, err := Offline{}.Verify(context.Background(), email)
		if err != nil || !r.Valid || r.Verdict != VerdictValid || r.Score != 1 || r.Provider != ProviderOffline {
			t.Errorf("Verify(%q) = %+v, %v; want valid", email, r, err)
		}
	}

	invalid := []string{"", "notanemail", "@example.com", "user@", "user@localhost", "user@.com", "user@@example.com", "user @example.com"}
	for _, email := range invalid {
		r, err := Offline{}.Verify(context.Background(), email)
		if err != nil || r.Valid || r.Verdict != VerdictInvalid || r.Score != 0 {
			t.Errorf("Verify(%q) = %+v, %v; want invalid", email, r, err)
		}
	}
}

func sendgridServer(t *testing.T, status int, body string) *sendgrid.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return sendgrid.New(srv.URL, "SG.key", nil)
}

func TestSendGrid(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Result
	}{
		{
			name: "valid",
			body: `{"result":{"verdict":"Valid","score":0.97}}`,
			want: Result{Valid: true, Verdict: VerdictValid, Score: 0.97},
		},
		{
			name: "risky role and disposable",
			body: `{"result":{"verdict":"Risky","score":0.5,"checks":{"domain":{"is_suspected_disposable_address":true},"local_part":{"is_suspected_role_address":true}}}}`,
			want: Result{Valid: true, Verdict: VerdictRisky, Score: 0.5, Disposable: true, Role: true},
		},
		{
			name: "invalid",
			body: `{"result":{"verdict":"Invalid","score":0.01}}`,
			want: Result{Valid: false, Verdict: VerdictInvalid, Score: 0.01},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := SendGrid{Client: sendgridServer(t, http.StatusOK, tc.body)}.Verify(context.Background(), "user@example.com")
			if err != nil {
				t.Fatal(err)
			}
			tc.want.Provider, tc.want.Raw = ProviderSendGrid, tc.body
			if *r != tc.want {
				t.Errorf("Verify() = %+v\nwant       %+v", *r, tc.want)
			}
		})
	}
}

func TestSendGrid_Error(t *testing.T) {
	_, err := SendGrid{Client: sendgridServer(t, http.StatusForbidden, `{}`)}.Verify(context.Background(), "user@example.com")
	if err == nil {
		t.Error("Verify() should return the api error")
	}
}

type countingVerifier struct{ calls int }

func (c *countingVerifier) Verify(context.Context, string) (*Result, error) {
	c.calls++
	return nil, errors.New("unavailable")
}

func TestAllowlist(t *testing.T) {
	next := &countingVerifier{}
	v := Allowlist{Domains: []string{"example.com"}, Next: next}

	r, err := v.Verify(context.Background(), "user@EXAMPLE.com")
	if err != nil || !r.Valid || r.Provider != ProviderAllowlist || next.calls != 0 {
		t.Errorf("allowlisted Verify() = %+v, %v (next called %d times)", r, err, next.calls)
	}

	// subdomains are not allowlisted
	if _, err := v.Verify(context.Background(), "user@sub.example.com"); err == nil || next.calls != 1 {
		t.Errorf("Verify() should defer to next for other domains (err %v, calls %d)", err, next.calls)
	}
}
