package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Notion() *config.Rule {
	// Define the identifiers that match the Keywords
	identifiers := []string{"ntn_"}

	// Define the regex pattern for Notion API token
	secretRegex := `ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`

	regex := utils.GenerateUniqueTokenRegex(secretRegex, false)

	r := config.Rule{
		Description: "Notion API token",
		ID:          "notion-api-token",
		Confidence:  "high",
		Regex:       regex,
		Keywords:    identifiers,
		FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	tps := []string{



	}

	fps := []string{
		"ntn_12345678901",
		"ntn_123456789012345678901234567890123456789012345678901234567890",
		"ntn_12345678901abc",
	}

	return utils.Validate(r, tps, fps)
}
