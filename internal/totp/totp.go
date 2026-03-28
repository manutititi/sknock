package totp

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Verify validates a 6-digit TOTP code against a base32 seed.
// Allows ±1 period (±30s) for clock skew.
func Verify(seed, code string) bool {
	valid, _ := totp.ValidateCustom(code, seed, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:     1,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

