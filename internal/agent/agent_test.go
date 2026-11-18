package agent

import (
	"testing"
	"time"
)

func TestValidateTTL(t *testing.T) {
	for _, d := range []time.Duration{MinTTL, DefaultTTL, MaxTTL} {
		if err := ValidateTTL(d); err != nil {
			t.Errorf("ValidateTTL(%s) = %v", d, err)
		}
	}
	for _, d := range []time.Duration{0, -time.Hour, MinTTL - time.Second, MaxTTL + time.Second} {
		if ValidateTTL(d) == nil {
			t.Errorf("ValidateTTL(%s) accepted", d)
		}
	}
}
