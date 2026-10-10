package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func DockerHubPersonalAccessToken() *config.Rule {
	r := config.Rule{
		ID:          "dockerhub-personal-access-token",
		Confidence:  "high",
		Description: "Detected a Docker Hub personal access token, which may expose Docker Hub account access.",
		Regex:       utils.GenerateUniqueTokenRegex(`dckr_pat_[A-Za-z0-9_-]{27}`, false),
		Keywords:    []string{"dckr_pat_"},
		FilterExpr:  utils.MinEntropy(3.5),
	}

	tps := []string{


	}
	return utils.Validate(r, tps, nil)
}

func DockerHubOrganizationAccessToken() *config.Rule {
	r := config.Rule{
		ID:          "dockerhub-organization-access-token",
		Confidence:  "high",
		Description: "Detected a Docker Hub organization access token, which may expose organization repositories.",
		Regex:       utils.GenerateUniqueTokenRegex(`dckr_oat_[A-Za-z0-9_-]{32}`, false),
		Keywords:    []string{"dckr_oat_"},
		FilterExpr:  utils.MinEntropy(3.5),
	}

	tps := []string{

	}
	return utils.Validate(r, tps, nil)
}
