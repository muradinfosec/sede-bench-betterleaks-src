package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func OpenAI() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "openai-api-key",
		Confidence:  "high",
		Description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false),
		Keywords: []string{
			"T3BlbkFJ",
		},
		ValidateExpr: `let r = http.get("https://api.openai.com/v1/models", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.json?.object ?? "") == "list" ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	}

	// validate
	tps := append(utils.GenerateSampleSecrets("openaiApiKey", "sk-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)+"T3BlbkFJ"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)),
		[]string{
			// Legacy project keys












		}...)
	return utils.Validate(r, tps, nil)
}
