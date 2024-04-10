# METADATA
# title: Github Action from Unverified Creator used
# description: |-
#   Usage of the following GitHub Actions repositories was detected in workflows
#   or composite actions, but their owner is not a verified creator.
# custom:
#   level: note
package rules.github_action_from_unverified_creator_used

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

github_verified_partners contains p if some p in ["1password", "42crunch", "actionforge", "actions", "acunetix360", "adobe", "advanced-security", "aikidosec", "algolia", "algorithmiaio", "algosec", "aliyun", "altostra", "anchore", "ansible", "apisec-inc", "appdome", "aquasecurity", "armbian", "armory", "asana", "athenianco", "atlanhq", "atlassian", "authzed", "autifyhq", "autometrics-dev", "aws-actions", "axosoft", "azure", "bearer", "beyondtrust", "bitovi", "boostsecurityio", "bridgecrewio", "browserstack", "buildkite", "buildless", "bump-sh", "bytebase", "charmbracelet", "checkmarx", "checkmarx-ts", "cloudflare", "cloud-maker-ai", "cloudnation-nl", "cloudposse", "cloudsmith-io", "coalfire", "codacy", "codeclimate", "codecov", "codefresh-io", "codesee-io", "configcat", "coverallsapp", "crowdstrike", "cyberark", "cypress-io", "dagger", "dapr", "databricks", "datadog", "datarobot-oss", "datreeio", "deepsourcecorp", "defensecode", "denoland", "dependabot", "depot", "designitetools", "determinatesystems", "devcontainers", "devcyclehq", "developermetrics", "devops-actions", "digitalocean", "docker", "elide-dev", "elmahio", "endorlabs", "ermetic", "errata-ai", "escape-technologies", "eviden-actions", "explore-dev", "expo", "facebook", "faros-ai", "fiberplane", "flatt-security", "formspree", "fortify", "fossas", "game-ci", "garden-io", "garnet-org", "genymobile", "getsentry", "git-for-windows", "github", "glueops", "gobeyondidentity", "gocardless", "godaddy", "goit", "golang", "google-github-actions", "goreleaser", "gorillastack", "graalvm", "gradle", "gruntwork-io", "guardsquare", "hashicorp", "honeycombio", "hopinc", "hubspot", "huggingface", "ibm", "infracost", "ionic-team", "iterative", "jetbrains", "jfrog", "jreleaser", "jscrambler", "keeper-security", "kittycad", "ksoclabs", "lacework", "lambdatest", "launchdarkly", "leanix", "legit-labs", "lightlytics", "lightstep", "linear-b", "liquibase", "liquibase-github-actions", "livecycle", "lob", "localstack", "mablhq", "matlab-actions", "mergifyio", "microsoft", "mobb-dev", "mobsf", "mockoon", "mondoohq", "nearform-actions", "netsparker", "newrelic", "nextchaptersoftware", "nightfallai", "nitrictech", "nobl9", "northflank", "noteable-io", "nowsecure", "nuget", "nullify-platform", "octokit", "octopusdeploy", "okteto", "olympix", "opencontextinc", "oracle-actions", "orcasecurity", "ossf", "oxsecurity", "pachyderm", "pagerduty", "paloaltonetworks", "pangeacyber", "paperspace", "parasoft", "perforce", "phrase", "phylum-dev", "planetscale", "plivo", "ponicode", "portswigger", "portswigger-cloud", "prefecthq", "probely", "projectdiscovery", "psalm", "pypa", "qualityclouds", "rainforestapp", "rapid7", "rapidapi", "readmeio", "redefinedev", "redhat-actions", "rematocorp", "restackio", "reversinglabs", "rigs-it", "rootlyhq", "ruby", "rubygems", "saucelabs", "scalacenter", "scaleway", "sec0ne", "securecodewarrior", "securestackco", "servicenow", "shipa-corp", "shipyard", "shopify", "shundor", "sigstore", "slackapi", "snaplet", "snyk", "sodadata", "solidify", "sonarsource", "soos-io", "sourcegraph", "spacelift-io", "speakeasy-api", "stackhawk", "stackql", "step-security", "sturdy-dev", "supabase", "superfly", "swdotcom", "swimmio", "synopsys-sig", "sysdiglabs", "tailscale", "taktile-org", "taraai", "teamwork", "teleport-actions", "testspace-com", "tidbcloud", "trufflesecurity", "trunk-io", "tryghost", "turbot", "twilio-labs", "typeform", "uffizzicloud", "upwindsecurity", "veracode", "verimatrix", "whiteducksoftware", "whitesource", "wpengine", "xpiritbv", "xygeni", "yesolutions", "zaproxy"]

# Consider input package namespaces as verified
github_verified_partners contains input.packages[_].package_namespace

results contains poutine.finding(
	rule,
	repo_purl,
	{"details": sprintf("Used in %d repo(s)", [count(unverified_github_actions[repo_purl])])},
)

unverified_github_actions[action_repo] contains pkg.purl if {
	pkg := input.packages[_]
	dep := array.concat(pkg.build_dependencies, pkg.package_dependencies)[_]
	startswith(dep, "pkg:githubactions/")

	action_repo := split(dep, "@")[0]
	not regex.match(sprintf("pkg:githubactions/(%s)/", [concat("|", github_verified_partners)]), dep)
}
