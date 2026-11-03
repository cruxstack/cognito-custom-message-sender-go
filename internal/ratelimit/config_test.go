package ratelimit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseConfig_Empty(t *testing.T) {
	for _, raw := range []string{"", "  ", "{}"} {
		cfg, err := ParseConfig(raw)
		if err != nil {
			t.Fatalf("ParseConfig(%q) error = %v", raw, err)
		}
		if !reflect.DeepEqual(cfg, DefaultConfig()) {
			t.Errorf("ParseConfig(%q) = %+v, want defaults", raw, cfg)
		}
	}
}

func TestParseConfig_Overrides(t *testing.T) {
	raw := `{
		"failMode": "closed",
		"metricNamespace": "Example/Email",
		"timeout": "250ms",
		"normalize": {"stripPlusTag": false},
		"exempt": {"domains": [" Example.COM "]},
		"global": {"mode": "enforce", "shards": 8},
		"classes": {
			"signup": {"destination": [{"window": "30m", "max": 2}], "global": [{"window": "1h", "max": 500}], "globalMode": "count"}
		}
	}`

	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if cfg.FailMode != FailClosed || cfg.MetricNamespace != "Example/Email" || cfg.Timeout != Duration(250*time.Millisecond) {
		t.Errorf("top-level overrides not applied: %+v", cfg)
	}
	if cfg.Normalize.StripPlusTag || !cfg.Normalize.StripGmailDots {
		t.Errorf("Normalize = %+v, want only stripPlusTag disabled", cfg.Normalize)
	}
	if want := []string{"example.com"}; !reflect.DeepEqual(cfg.Exempt.Domains, want) {
		t.Errorf("Exempt.Domains = %v, want %v", cfg.Exempt.Domains, want)
	}
	if want := []string{ClassAdmin}; !reflect.DeepEqual(cfg.Exempt.Classes, want) {
		t.Errorf("Exempt.Classes = %v, want default %v", cfg.Exempt.Classes, want)
	}
	if cfg.Global.Mode != ModeEnforce || cfg.Global.Shards != 8 || cfg.Global.DegradeFraction != 0.8 {
		t.Errorf("Global = %+v", cfg.Global)
	}

	signup := cfg.Classes[ClassSignUp]
	if want := []Limit{{Window(30 * time.Minute), 2}}; !reflect.DeepEqual(signup.Destination, want) {
		t.Errorf("signup destination = %v, want %v", signup.Destination, want)
	}
	if cfg.GlobalMode(ClassSignUp) != ModeCount || cfg.GlobalMode(ClassAuthentication) != ModeEnforce {
		t.Errorf("GlobalMode() signup = %q, authentication = %q", cfg.GlobalMode(ClassSignUp), cfg.GlobalMode(ClassAuthentication))
	}
	if !reflect.DeepEqual(cfg.Classes[ClassAuthentication], DefaultConfig().Classes[ClassAuthentication]) {
		t.Error("classes not in the document should keep their defaults")
	}
}

func TestParseConfig_Errors(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"invalid json", `{`, "failed to parse"},
		{"unknown field", `{"failmod": "open"}`, "unknown field"},
		{"trailing data", `{} {}`, "unexpected data"},
		{"fail mode", `{"failMode": "maybe"}`, "failMode"},
		{"namespace reserved", `{"metricNamespace": "AWS/Lambda"}`, "metricNamespace"},
		{"namespace empty", `{"metricNamespace": ""}`, "metricNamespace"},
		{"timeout zero", `{"timeout": "0s"}`, "timeout"},
		{"timeout too long", `{"timeout": "11s"}`, "timeout"},
		{"timeout syntax", `{"timeout": "soon"}`, "invalid duration"},
		{"dedupe ttl", `{"dedupeTtl": "30s"}`, "dedupeTtl"},
		{"user key", `{"userKey": "email"}`, "userKey"},
		{"exempt class", `{"exempt": {"classes": ["marketing"]}}`, "exempt.classes"},
		{"exempt domain", `{"exempt": {"domains": [" "]}}`, "exempt.domains"},
		{"global mode", `{"global": {"mode": "block"}}`, "global.mode"},
		{"shards zero", `{"global": {"shards": 0}}`, "global.shards"},
		{"shards too many", `{"global": {"shards": 101}}`, "global.shards"},
		{"degrade zero", `{"global": {"degradeFraction": 0}}`, "degradeFraction"},
		{"degrade over one", `{"global": {"degradeFraction": 1.5}}`, "degradeFraction"},
		{"unknown class", `{"classes": {"marketing": {}}}`, "unknown class"},
		{"class global mode", `{"classes": {"signup": {"globalMode": "block"}}}`, "globalMode"},
		{"window syntax", `{"classes": {"signup": {"destination": [{"window": "1w", "max": 1}]}}}`, "invalid window"},
		{"window zero", `{"classes": {"signup": {"destination": [{"window": "0m", "max": 1}]}}}`, "invalid window"},
		{"window missing", `{"classes": {"signup": {"destination": [{"max": 1}]}}}`, "window is required"},
		{"window number", `{"classes": {"signup": {"destination": [{"window": 60, "max": 1}]}}}`, "window must be a string"},
		{"max zero", `{"classes": {"signup": {"user": [{"window": "1h", "max": 0}]}}}`, "positive integer"},
		{"max negative", `{"classes": {"signup": {"global": [{"window": "1h", "max": -1}]}}}`, "positive integer"},
		{"duplicate window", `{"classes": {"signup": {"destination": [{"window": "60m", "max": 1}, {"window": "1h", "max": 2}]}}}`, "duplicated"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParseConfig() error = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantStr string
		wantErr bool
	}{
		{"30s", 30 * time.Second, "30s", false},
		{"15m", 15 * time.Minute, "15m", false},
		{"60m", time.Hour, "1h", false},
		{"90m", 90 * time.Minute, "90m", false},
		{"24h", 24 * time.Hour, "1d", false},
		{"36h", 36 * time.Hour, "36h", false},
		{"7d", 7 * 24 * time.Hour, "7d", false},
		{"0s", 0, "", true},
		{"01m", 0, "", true},
		{"-1m", 0, "", true},
		{"1.5h", 0, "", true},
		{"1h30m", 0, "", true},
		{"15", 0, "", true},
		{"m", 0, "", true},
		{"1ms", 0, "", true},
		{"1M", 0, "", true},
		{"", 0, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			w, err := ParseWindow(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseWindow(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if time.Duration(w) != tc.want || w.String() != tc.wantStr {
				t.Errorf("ParseWindow(%q) = %v (%s), want %v (%s)", tc.in, time.Duration(w), w, tc.want, tc.wantStr)
			}
		})
	}
}

func TestConfig_JSONRoundTrip(t *testing.T) {
	bs, err := json.Marshal(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(string(bs))
	if err != nil {
		t.Fatalf("ParseConfig(marshaled defaults) error = %v\n%s", err, bs)
	}
	if !reflect.DeepEqual(cfg, DefaultConfig()) {
		t.Errorf("round trip changed the config:\n%s", bs)
	}
}
