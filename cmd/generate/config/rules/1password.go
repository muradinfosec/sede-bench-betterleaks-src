package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://developer.1password.com/docs/service-accounts/security/?token-example=encoded
func OnePasswordServiceAccountToken() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "1password-service-account-token",
		Confidence:  "high",
		Description: "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.",
		Regex:       `ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`,
		Keywords:    []string{"ops_eyj"},
		ValidateExpr: `let r = http.get("https://events.1password.com/api/v2/auth/introspect", {
    "Accept": "application/json",
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains "\"features\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("1password", secrets.NewSecretWithEntropy(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`, 4)),
		`### 1Password System Vault Name

`,


	}
	fps := []string{
		// Invalid
		`        login:
          serviceAccountToken:
            fn::secret: ops_eyJzaWduSW5B..[Redacted]`,
		`: To start using this service account, run the following command:
:
: export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWduSW5BZGRyZXNzIjoiaHR0cHM6...`,
		// Low entropy.

	}
	return utils.Validate(r, tps, fps)
}

// Reference:
// - https://1passwordstatic.com/files/security/1password-white-paper.pdf
func OnePasswordSecretKey() *config.Rule {
	// 1Password secret keys include several hyphens but these are only for readability
	// and are stripped during 1Password login. This means that the following are technically
	// the same valid key:
	//   - A3ASWWYB798JRYLJVD423DC286TVMH43EB
	//   - A-3-A-S-W-W-Y-B-7-9-8-J-R-Y-L-J-V-D-4-2-3-D-C-2-8-6-T-V-M-H-4-3-E-B
	// But in practice, when these keys are added to a vault, exported in an emergency kit, or
	// copied, they have hyphens that follow one of two patterns I can find:
	//   - A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB (every key I've generated has this pattern)
	//   - A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB  (the whitepaper includes this example, which could just be a typo)
	// To avoid a complicated regex that checks for every possible situation it's probably best
	// to scan for the these two patterns.
	r := config.Rule{
		Description: "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.",
		ID:          "1password-secret-key",
		Confidence:  "high",
		Regex:       `\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`,
		Keywords:    []string{"A3-"},
		FilterExpr:  `entropy(finding["secret"]) <= 3.8`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("1password", secrets.NewSecretWithEntropy(`A3-[A-Z0-9]{6}-[A-Z0-9]{11}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`, 3.8))
	tps = append(tps, utils.GenerateSampleSecrets("1password", secrets.NewSecretWithEntropy(`A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`, 3.8))...)
	tps = append(tps,
		// from whitepaper
		`A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB`,
		`A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB`,
	)
	fps := []string{
		// low entropy
		`A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX`,
		// lowercase
		`A3-xXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`,
	}
	return utils.Validate(r, tps, fps)
}
