package smssender

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParsePhoneNumber(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantErr      bool
		wantNumber   string
		wantCountry  string
		wantCalling  string
		wantNational string
		wantValid    bool
		wantPossible bool
	}{
		{"us e164", "+12065550100", false, "+12065550100", "US", "1", "2065550100", true, true},
		{"us formatted", " +1 (206) 555-0100 ", false, "+12065550100", "US", "1", "2065550100", true, true},
		{"gb", "+442079460000", false, "+442079460000", "GB", "44", "2079460000", true, true},
		{"it keeps leading zero", "+390612345678", false, "+390612345678", "IT", "39", "0612345678", true, true},
		{"single region code but invalid", "+4912", false, "+4912", "DE", "49", "12", false, true},
		{"shared calling code and invalid", "+4412", true, "", "", "", "", false, false},
		{"shared calling code and no region", "+15555550100", true, "", "", "", "", false, false},
		{"non-geographic", "+80012345678", true, "", "", "", "", false, false},
		{"missing plus", "2065550100", true, "", "", "", "", false, false},
		{"not a number", "not-a-phone-number", true, "", "", "", "", false, false},
		{"empty", "", true, "", "", "", "", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePhoneNumber(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParsePhoneNumber(%q) error = %v, wantErr %v (got %+v)", tc.in, err, tc.wantErr, got)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidPhoneNumber) {
					t.Errorf("error = %v, want ErrInvalidPhoneNumber", err)
				}
				return
			}
			if got.Number != tc.wantNumber || got.Country != tc.wantCountry || got.CountryCallingCode != tc.wantCalling ||
				got.NationalNumber != tc.wantNational || got.IsValid != tc.wantValid || got.IsPossible != tc.wantPossible {
				t.Errorf("ParsePhoneNumber(%q) = %+v", tc.in, got)
			}
			if got.CarrierCode != nil {
				t.Errorf("CarrierCode = %q, want nil", *got.CarrierCode)
			}
		})
	}
}

func TestPhoneNumber_JSONMatchesNodeSender(t *testing.T) {
	p, err := ParsePhoneNumber("+12065550100")
	if err != nil {
		t.Fatal(err)
	}
	bs, _ := json.Marshal(p)
	want := `{"carrierCode":null,"countryCallingCode":"1","country":"US","nationalNumber":"2065550100","number":"+12065550100","isValid":true,"isPossible":true}`
	if string(bs) != want {
		t.Errorf("json = %s\nwant   %s", bs, want)
	}
}

func TestMaskPhoneNumber(t *testing.T) {
	tests := map[string]string{
		"+12065550100": "+*******0100",
		"2065550100":   "******0100",
		"+1234":        "+***",
		"1234":         "***",
		"":             "",
	}
	for in, want := range tests {
		if got := MaskPhoneNumber(in); got != want {
			t.Errorf("MaskPhoneNumber(%q) = %q, want %q", in, got, want)
		}
	}
}
