package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func CockroachLabsCloudAPIKey() *config.Rule {
	r := config.Rule{
		ID:          "cockroachlabs-cloud-api-key",
		Confidence:  "high",
		Description: "Detected a CockroachDB Cloud service account API key, which may allow unauthorized access to CockroachDB Cloud resources.",
		Regex:       `\b(CCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40})\b`,
		Keywords:    []string{"CCDB1_"},
		ValidateExpr: `let r = http.get("https://cockroachlabs.cloud/api/v1/clusters", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"clusters\"") && (r.body contains "\"pagination\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: `entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{



	}
	fps := []string{
		`CCDB1_short_9HUwzxJDBGpEvtbN3HjJb7L7zirVo3qSCAi1MCct`,
	}
	return utils.Validate(r, tps, fps)
}
