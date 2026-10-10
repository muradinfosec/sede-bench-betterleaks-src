package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func CratesIOAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "crates-io-api-key",
		Confidence:  "high",
		Description: "crates.io API key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`crates(?:[_.-]?io)?`}, `cio[A-Za-z0-9]{32}`, true),
		Keywords:    []string{"crates"},
		ValidateExpr: `let r = http.get("https://crates.io/api/v1/me", {
    "Authorization": finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	// validate
	tps := []string{

	}
	fps := []string{
		`cio_short`,
	}
	return utils.Validate(r, tps, fps)
}
