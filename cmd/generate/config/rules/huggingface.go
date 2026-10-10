package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

const huggingFaceValidateExpr = `let r = http.get("https://huggingface.co/api/whoami-v2", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid",
    "analysis": {
      "id": (r.json?.id ?? ""),
      "username": (r.json?.name ?? ""),
      "name": (r.json?.fullname ?? ""),
      "email": (r.json?.email ?? ""),
      "orgs": (r.json?.orgs ?? []),
      "auth": (r.json?.auth ?? {})
    }
  } : r.status == 401 && (r.body contains "expired") ? {
    "result": "revoked",
    "reason": "Token expired"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

// whoami-v2 returns token grants, including their resource scopes. Organization
// policies and the owner's access can restrict their use further. Membership
// alone does not establish fine-grained access.
// https://huggingface.co/.well-known/openapi.json
// https://huggingface.co/docs/hub/security-tokens
// Permission names: Hugging Face's FineGrainedToken/ViewUtils definitions.
// Inference invocation is not a data write, and configuring secrets does not
// establish the ability to read secret values.
const huggingFaceAnalyzeExpr = `let input = validation.analysis;
let auth = input["auth"] ?? {};
let access_token = auth["accessToken"] ?? {};
let role = access_token["role"] ?? "";
let orgs = input["orgs"] ?? [];
let fine_grained = role == "fineGrained" ? (access_token["fineGrained"] ?? {}) : {};
let global = fine_grained["global"] ?? [];
let scoped = fine_grained["scoped"] ?? [];
let permissions = sort(uniq(concat(global, flatten(map(scoped, {#.permissions ?? []})))));
let gated = fine_grained["canReadGatedRepos"] ?? false;
let capabilities = analysis.capabilities({
  "read": role in ["read", "write"] || gated || any(permissions, {# in [
    "repo.read", "repo.content.read", "repo.content.metadata.read", "repo.lfs.read",
    "repo.config.read", "repo.access.read", "collection.read", "org.read", "org.members.read",
    "user.billing.read", "user.notifications.read", "user.membership.read",
    "inference.endpoints.read", "job.read"
  ]}),
  "write": role == "write" || any(permissions, {# in [
    "repo.write", "repo.content.write", "repo.config.write", "repo.config.doi.write",
    "repo.config.visibility.write", "repo.config.variables.write", "repo.config.secrets.write",
    "repo.access.write", "discussion.write", "post.write", "collection.write",
    "inference.endpoints.write", "job.write"
  ]}),
  "manage_users": any(permissions, {# in ["org.write", "org.members.write"]})
});
{
  "reason": len(capabilities) > 0 ? "" : "Hugging Face returned no recognized permission grants",
  "metadata": role == "fineGrained" ? {
    "role": role,
    "token_name": access_token["displayName"] ?? "",
    "permissions": permissions
  } : (role == "" ? {} : {"role": role}),
  "identity": {
    "id": string(input["id"] ?? ""),
    "username": input["username"] ?? "",
    "name": input["name"] ?? "",
    "email": input["email"] ?? "",
    "account": role != "fineGrained" && len(orgs) == 1 ? {
      "id": string(orgs[0]?.id ?? ""),
      "name": orgs[0]?.name ?? ""
    } : {}
  },
  "capabilities": capabilities
}`

// The provider documents immediate, global invalidation of matching tokens on
// 202, while deliberately not disclosing whether the submitted token existed.
// https://huggingface.co/docs/hub/security-tokens#revoking-a-leaked-token
const huggingFaceRevokeExpr = `let r = http.post("https://huggingface.co/api/credentials/revoke", {
  "Content-Type": "application/json"
}, toJSON({"credentials": [finding["secret"]]}));
r.status == 202 ? {
  "result": "revoked",
  "reason": "Hugging Face invalidated any matching token; prior token validity is not disclosed"
} : revoke.unknown(r)`

// Reference: https://huggingface.co/docs/hub/security-tokens
//
// Old tokens have the prefix `api_`, however, I am not sure it's worth detecting them as that would be high noise.
// https://huggingface.co/docs/api-inference/quicktour
func HuggingFaceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "huggingface-access-token",
		Confidence:  "high",
		Description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
		Regex:       utils.GenerateUniqueTokenRegex("hf_(?i:[a-z]{34})", false),
		Keywords: []string{
			"hf_",
		},
		ValidateExpr: huggingFaceValidateExpr,
		AnalyzeExpr:  huggingFaceAnalyzeExpr,
		RevokeExpr:   huggingFaceRevokeExpr,
		FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("huggingface", "hf_"+secrets.NewSecretWithEntropy("[a-zA-Z]{34}", 2))
	tps = append(tps,














		`# Not critical, only usable on the sandboxed CI instance.


	)
	fps := []string{
		`- (id)hf_requiredCharacteristicTypesForDisplayMetadata;`,
		`amazon.de#@#div[data-cel-widget="desktop-rhf_SponsoredProductsRemoteRHFSearchEXPSubsK2ClickPagination"]`,
		`                            _kHMSymptomhf_generatedByHomeAppForDebuggingPurposesKey,`,
		`    #define OSCHF_DebugGetExpectedAverageCrystalAmplitude NOROM_OSCHF_DebugGetExpectedAverageCrystalAmplitude`,
		`  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2, &hf_servingcellpriorityparametersdescription_h_prio),`,
		`+HWI-ST565_0092:4:1101:5508:5860#ACTTGA/1
		bb_eeeeegfgffhiiiiiiiiiiihiiiiicgafhf_eefghihhiiiifhifhhdhifhiiiihifdgdhggf\bbceceedbcd
		@HWI-ST565_0092:4:1101:7621:5770#ACTTGA/1`,
		`y{}x|~|}{~}}~|~}||�~|�{��|{}{|~z{}{{|{||{|}|{}{~|y}vjoePbUBJ7&;";  <; :;?!!;<7%$IACa_ecghbfbaebejhahfbhf_ddbficghbgfbhhcghdghfhigiifhhehhdggcgfchf_fgcei^[[.40&54"5666 6`,
		`                    change_dir(cwd)
		subdirs = glob.glob('HF_CAASIMULIAComputeServicesBuildTime.HF*.Linux64')
		if len(subdirs) == 1:`,
		`        os.environ.get("HF_AUTH_TOKEN",
		"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),`,
		`# HuggingFace API Token https://huggingface.co/settings/tokens
		HUGGINGFACE_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,`,
	}
	return utils.Validate(r, tps, fps)
}

// Will be deprecated Aug 1st, 2023.
func HuggingFaceOrganizationApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "huggingface-organization-api-token",
		Confidence:  "high",
		Description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
		Regex:       utils.GenerateUniqueTokenRegex("api_org_(?i:[a-z]{34})", false),
		Keywords: []string{
			"api_org_",
		},
		ValidateExpr: huggingFaceValidateExpr,
		AnalyzeExpr:  huggingFaceAnalyzeExpr,
		RevokeExpr:   huggingFaceRevokeExpr,
		FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("huggingface", "api_org_"+secrets.NewSecretWithEntropy("[a-zA-Z]{34}", 2))
	tps = append(tps,







		`def test_private_space(self):

        io = gr.load(`,



		fmt.Sprintf("api_org_%s", secrets.NewSecretWithEntropy(`[a-zA-Z]{34}`, 2)),
	)
	fps := []string{
		`public static final String API_ORG_EXIST = "APIOrganizationExist";`,
		`const api_org_controller = require('../../controllers/api/index').organizations;`,
		`API_ORG_CREATE("https://qyapi.weixin.qq.com/cgi-bin/department/create?access_token=ACCESS_TOKEN"),`,
		`def test_internal_api_org_inclusion_with_href(api_name, href, expected, monkeypatch, called_with):
		monkeypatch.setattr("requests.sessions.Session.request", called_with)`,
		`    def _api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a(self, method, url, body, headers):
        body = self.fixtures.load("api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a.xml")
        return httplib.OK, body, headers, httplib.responses[httplib.OK]`,

		`  From Hugging Face docs:

		If you do not submit your API token when sending requests to the API, you will not be able to run inference on your private models.`,
	}
	return utils.Validate(r, tps, fps)
}
