package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func RainforestPayProductionAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "rainforest-pay-production-api-key",
		Confidence:  "medium",
		Description: "Rainforest Pay production API key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`rainforest(?:[_. -]*pay)?(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`apikey_[a-f0-9]{64}`,
			false,
		),
		Keywords: []string{"rainforest"},
		ValidateExpr: `let r = http.get("https://api.rainforestpay.com/v1/merchants?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Rainforest-Api-Version": "2024-10-16",
    "Accept": "application/json"
  }); r.status == 200 && (r.json?.status ?? "") == "SUCCESS" ? {
    "result": "valid"
  } : r.status == 403 && (r.json?.status ?? "") == "ERROR" ? {
    "result": "valid",
    "reason": "Authenticated but merchant access is restricted"
  } : r.status == 401 && (r.json?.status ?? "") == "ERROR" ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"RAINFOREST_API_KEY=apikey_" + secrets.NewSecretWithEntropy(`[a-f0-9]{64}`, 3.5),
	}
	fps := []string{



	}
	return utils.Validate(r, tps, fps)
}
