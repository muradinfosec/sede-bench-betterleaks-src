package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func MaxMindLicenseKey() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "maxmind-license-key",
		Confidence:  "high",
		Description: "Discovered a potential MaxMind license key.",
		Regex:       utils.GenerateUniqueTokenRegex(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`, false),
		Keywords:    []string{"_mmk"},
		FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	}

	// validate

	return utils.Validate(r, tps, nil)
}
