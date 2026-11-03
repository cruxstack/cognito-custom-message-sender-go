package smssender

import (
	"errors"
	"strconv"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

var ErrInvalidPhoneNumber = errors.New("user phone number is not valid")

// PhoneNumber is the parsed destination passed to the policy as
// input.phoneNumberData. Field names match the earlier node.js sender so
// existing policies keep working.
type PhoneNumber struct {
	CarrierCode        *string `json:"carrierCode"`
	CountryCallingCode string  `json:"countryCallingCode"`
	Country            string  `json:"country"`
	NationalNumber     string  `json:"nationalNumber"`
	Number             string  `json:"number"`
	IsValid            bool    `json:"isValid"`
	IsPossible         bool    `json:"isPossible"`
}

// ParsePhoneNumber parses an international (+ prefixed) phone number. It
// fails when the number can't be parsed or doesn't map to a country, which
// includes non-geographic numbers. A number that maps to a country but isn't
// valid is returned with IsValid false so the policy can decide.
func ParsePhoneNumber(s string) (*PhoneNumber, error) {
	num, err := phonenumbers.Parse(strings.TrimSpace(s), "")
	if err != nil {
		return nil, ErrInvalidPhoneNumber
	}

	region := phonenumbers.GetRegionCodeForNumber(num)
	if region == "" || region == phonenumbers.UNKNOWN_REGION || region == "001" {
		return nil, ErrInvalidPhoneNumber
	}

	var carrier *string
	if c := num.GetPreferredDomesticCarrierCode(); c != "" {
		carrier = &c
	}

	return &PhoneNumber{
		CarrierCode:        carrier,
		CountryCallingCode: strconv.Itoa(int(num.GetCountryCode())),
		Country:            region,
		NationalNumber:     phonenumbers.GetNationalSignificantNumber(num),
		Number:             phonenumbers.Format(num, phonenumbers.E164),
		IsValid:            phonenumbers.IsValidNumber(num),
		IsPossible:         phonenumbers.IsPossibleNumber(num),
	}, nil
}

// MaskPhoneNumber hides all but the last four digits, for example
// "+*******5555".
func MaskPhoneNumber(s string) string {
	if len(s) <= 4 {
		if s == "" {
			return ""
		}
		return "***"
	}
	prefix := ""
	if strings.HasPrefix(s, "+") {
		prefix, s = "+", s[1:]
	}
	if len(s) <= 4 {
		return prefix + "***"
	}
	return prefix + strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}
