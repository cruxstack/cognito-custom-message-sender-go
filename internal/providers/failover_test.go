package providers

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cruxstack/cognito-custom-message-sender-go/internal/types"
)

// mockProvider is a test provider that can be configured to fail or succeed
type mockProvider struct {
	name      string
	sendErr   error
	healthy   bool
	sendCount int
	mu        sync.Mutex
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Send(ctx context.Context, d *types.EmailData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendCount++
	return m.sendErr
}

func (m *mockProvider) IsHealthy(ctx context.Context) bool {
	return m.healthy
}

func (m *mockProvider) GetSendCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendCount
}

func TestFailoverProvider_SendsToFirstHealthyProvider(t *testing.T) {
	primary := &mockProvider{name: "ses", healthy: true}
	secondary := &mockProvider{name: "sendgrid", healthy: true}

	fp := NewFailoverProvider([]Provider{primary, secondary})

	emailData := &types.EmailData{
		DestinationAddress: "test@example.com",
		SourceAddress:      "from@example.com",
		Providers: &types.EmailProviderMap{
			SES:      &types.EmailProviderData{TemplateID: "template-ses"},
			SendGrid: &types.EmailProviderData{TemplateID: "template-sg"},
		},
	}

	err := fp.Send(context.Background(), emailData)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if primary.GetSendCount() != 1 {
		t.Errorf("expected primary to be called once, got %d", primary.GetSendCount())
	}
	if secondary.GetSendCount() != 0 {
		t.Errorf("expected secondary to not be called, got %d", secondary.GetSendCount())
	}
}

func TestFailoverProvider_SkipsUnhealthyProvider(t *testing.T) {
	primary := &mockProvider{name: "ses", healthy: false}
	secondary := &mockProvider{name: "sendgrid", healthy: true}

	fp := NewFailoverProvider([]Provider{primary, secondary})

	emailData := &types.EmailData{
		DestinationAddress: "test@example.com",
		SourceAddress:      "from@example.com",
		Providers: &types.EmailProviderMap{
			SES:      &types.EmailProviderData{TemplateID: "template-ses"},
			SendGrid: &types.EmailProviderData{TemplateID: "template-sg"},
		},
	}

	err := fp.Send(context.Background(), emailData)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if primary.GetSendCount() != 0 {
		t.Errorf("expected primary to be skipped (unhealthy), got %d calls", primary.GetSendCount())
	}
	if secondary.GetSendCount() != 1 {
		t.Errorf("expected secondary to be called once, got %d", secondary.GetSendCount())
	}
}

func TestFailoverProvider_FailsOverOnSendError(t *testing.T) {
	primary := &mockProvider{name: "ses", healthy: true, sendErr: errors.New("send failed")}
	secondary := &mockProvider{name: "sendgrid", healthy: true}

	fp := NewFailoverProvider([]Provider{primary, secondary})

	emailData := &types.EmailData{
		DestinationAddress: "test@example.com",
		SourceAddress:      "from@example.com",
		Providers: &types.EmailProviderMap{
			SES:      &types.EmailProviderData{TemplateID: "template-ses"},
			SendGrid: &types.EmailProviderData{TemplateID: "template-sg"},
		},
	}

	err := fp.Send(context.Background(), emailData)

	if err != nil {
		t.Fatalf("expected no error (should failover), got: %v", err)
	}
	if primary.GetSendCount() != 1 {
		t.Errorf("expected primary to be called once, got %d", primary.GetSendCount())
	}
	if secondary.GetSendCount() != 1 {
		t.Errorf("expected secondary to be called once, got %d", secondary.GetSendCount())
	}
}

func TestFailoverProvider_WarnsAndReturnsNilWhenAllFail(t *testing.T) {
	primary := &mockProvider{name: "ses", healthy: true, sendErr: errors.New("primary failed")}
	secondary := &mockProvider{name: "sendgrid", healthy: true, sendErr: errors.New("secondary failed")}

	fp := NewFailoverProvider([]Provider{primary, secondary})

	emailData := &types.EmailData{
		DestinationAddress: "test@example.com",
		SourceAddress:      "from@example.com",
		Providers: &types.EmailProviderMap{
			SES:      &types.EmailProviderData{TemplateID: "template-ses"},
			SendGrid: &types.EmailProviderData{TemplateID: "template-sg"},
		},
	}

	err := fp.Send(context.Background(), emailData)

	// Returns nil to avoid Lambda retries - email is lost but logged
	if err != nil {
		t.Fatalf("expected nil error (warns only), got: %v", err)
	}
	if primary.GetSendCount() != 1 {
		t.Errorf("expected primary to be called once, got %d", primary.GetSendCount())
	}
	if secondary.GetSendCount() != 1 {
		t.Errorf("expected secondary to be called once, got %d", secondary.GetSendCount())
	}
}

func TestFailoverProvider_SkipsProviderWithoutConfig(t *testing.T) {
	primary := &mockProvider{name: "ses", healthy: true}
	secondary := &mockProvider{name: "sendgrid", healthy: true}

	fp := NewFailoverProvider([]Provider{primary, secondary})

	// Only SES config, no SendGrid config
	emailData := &types.EmailData{
		DestinationAddress: "test@example.com",
		SourceAddress:      "from@example.com",
		Providers: &types.EmailProviderMap{
			SES: &types.EmailProviderData{TemplateID: "template-ses"},
			// SendGrid is nil
		},
	}

	err := fp.Send(context.Background(), emailData)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if primary.GetSendCount() != 1 {
		t.Errorf("expected primary (ses) to be called, got %d", primary.GetSendCount())
	}
	if secondary.GetSendCount() != 0 {
		t.Errorf("expected secondary (sendgrid) to be skipped (no config), got %d", secondary.GetSendCount())
	}
}

func TestFailoverProvider_WarnsWhenNoProvidersAvailable(t *testing.T) {
	primary := &mockProvider{name: "ses", healthy: false}
	secondary := &mockProvider{name: "sendgrid", healthy: false}

	fp := NewFailoverProvider([]Provider{primary, secondary})

	emailData := &types.EmailData{
		DestinationAddress: "test@example.com",
		SourceAddress:      "from@example.com",
		Providers: &types.EmailProviderMap{
			SES:      &types.EmailProviderData{TemplateID: "template-ses"},
			SendGrid: &types.EmailProviderData{TemplateID: "template-sg"},
		},
	}

	err := fp.Send(context.Background(), emailData)

	// Returns nil to avoid Lambda retries - email is lost but logged
	if err != nil {
		t.Fatalf("expected nil error (warns only), got: %v", err)
	}
	// Neither provider should have been called (both unhealthy)
	if primary.GetSendCount() != 0 {
		t.Errorf("expected primary to be skipped, got %d calls", primary.GetSendCount())
	}
	if secondary.GetSendCount() != 0 {
		t.Errorf("expected secondary to be skipped, got %d calls", secondary.GetSendCount())
	}
}

func TestFailoverProvider_Name(t *testing.T) {
	fp := NewFailoverProvider([]Provider{})
	if fp.Name() != "failover" {
		t.Errorf("expected name 'failover', got '%s'", fp.Name())
	}
}

func TestHasProviderConfig(t *testing.T) {
	tests := []struct {
		name         string
		emailData    *types.EmailData
		providerName string
		expected     bool
	}{
		{
			name:         "nil providers",
			emailData:    &types.EmailData{},
			providerName: "ses",
			expected:     false,
		},
		{
			name: "ses with config",
			emailData: &types.EmailData{
				Providers: &types.EmailProviderMap{
					SES: &types.EmailProviderData{TemplateID: "template"},
				},
			},
			providerName: "ses",
			expected:     true,
		},
		{
			name: "ses without template ID",
			emailData: &types.EmailData{
				Providers: &types.EmailProviderMap{
					SES: &types.EmailProviderData{},
				},
			},
			providerName: "ses",
			expected:     false,
		},
		{
			name: "sendgrid with config",
			emailData: &types.EmailData{
				Providers: &types.EmailProviderMap{
					SendGrid: &types.EmailProviderData{TemplateID: "template"},
				},
			},
			providerName: "sendgrid",
			expected:     true,
		},
		{
			name: "unknown provider",
			emailData: &types.EmailData{
				Providers: &types.EmailProviderMap{
					SES: &types.EmailProviderData{TemplateID: "template"},
				},
			},
			providerName: "unknown",
			expected:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hasProviderConfig(tc.emailData, tc.providerName)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}
