package sendgrid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type recorded struct {
	path, auth string
	body       map[string]any
}

func server(t *testing.T, status int, response string) (*httptest.Server, *recorded) {
	t.Helper()
	rec := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path, rec.auth = r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &rec.body); err != nil {
			t.Errorf("request body is not json: %s", b)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func TestSendTemplate(t *testing.T) {
	srv, rec := server(t, http.StatusAccepted, "")
	c := New(srv.URL+"/", "SG.key", nil)

	err := c.SendTemplate(context.Background(), TemplateEmail{
		From:       "ACME <no-reply@example.com>",
		To:         "user@example.com",
		TemplateID: "d-123",
		Data:       map[string]any{"code": "123456"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if rec.path != "/v3/mail/send" || rec.auth != "Bearer SG.key" {
		t.Errorf("request = %s with auth %q", rec.path, rec.auth)
	}
	want := `{"from":{"email":"no-reply@example.com","name":"ACME"},"personalizations":[{"dynamic_template_data":{"code":"123456"},"to":[{"email":"user@example.com"}]}],"template_id":"d-123"}`
	if got, _ := json.Marshal(rec.body); string(got) != want {
		t.Errorf("body = %s\nwant   %s", got, want)
	}
}

func TestSendTemplate_APIError(t *testing.T) {
	srv, _ := server(t, http.StatusUnauthorized, `{"errors":[{"message":"bad key"}]}`)
	err := New(srv.URL, "SG.bad", nil).SendTemplate(context.Background(), TemplateEmail{From: "a@example.com", To: "b@example.com"})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized || apiErr.Body == "" {
		t.Errorf("error = %v, want an APIError with the status and body", err)
	}
}

func TestValidateEmail(t *testing.T) {
	srv, rec := server(t, http.StatusOK, `{"result":{
		"email":"admin@mailinator.com","verdict":"Risky","score":0.5,
		"checks":{
			"domain":{"has_valid_address_syntax":true,"has_mx_or_a_record":true,"is_suspected_disposable_address":true},
			"local_part":{"is_suspected_role_address":true},
			"additional":{"has_known_bounces":false,"has_suspected_bounces":false}
		}
	}}`)

	v, raw, err := New(srv.URL, "SG.key", nil).ValidateEmail(context.Background(), "admin@mailinator.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.path != "/v3/validations/email" || rec.body["email"] != "admin@mailinator.com" || rec.body["source"] != "cognito" {
		t.Errorf("request = %s %v", rec.path, rec.body)
	}
	if v.Verdict != VerdictRisky || v.Score != 0.5 || !v.Checks.Domain.IsSuspectedDisposableAddress || !v.Checks.LocalPart.IsSuspectedRoleAddress {
		t.Errorf("validation = %+v", v)
	}
	if len(raw) == 0 {
		t.Error("raw response should be returned")
	}
}

func TestValidateEmail_BadJSON(t *testing.T) {
	srv, _ := server(t, http.StatusOK, `not json`)
	if _, _, err := New(srv.URL, "SG.key", nil).ValidateEmail(context.Background(), "a@example.com"); err == nil {
		t.Error("ValidateEmail() should fail on an invalid response")
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	if c := New("", "k", nil); c.baseURL != DefaultBaseURL || c.http.Timeout == 0 {
		t.Errorf("client = %+v", c)
	}
}
