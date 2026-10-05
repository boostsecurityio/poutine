# METADATA
# title: GitHub Action from Unverified Creator used
# description: |-
#   Usage of the following GitHub Actions repositories was detected in workflows
#   or composite actions, but their owner is not a verified creator.
# custom:
#   level: note
package rules.github_action_from_unverified_creator_used

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

# Regenerate with make update-verified-creators.
github_verified_partners contains p if some p in ["1password", "42crunch", "accuknox", "actions", "activitysmithhq", "acunetix360", "adobe", "advanced-security", "aikidosec", "airbytehq", "akeyless-community", "algolia", "algorithmiaio", "algosec", "aliyun", "amplify-security", "anchore", "ansible", "anthropics", "antithesishq", "apify", "apisec-inc", "apollographql", "apollographql-gh-actions", "appdome", "appknox", "aquasecurity", "armbian", "armory", "arnica-io", "asana", "astral-sh", "astronomer", "aswincloud", "athenianco", "athombv", "atlanhq", "atos-actions", "augmentcode", "authzed", "autifyhq", "autometrics-dev", "aws-actions", "azure", "bearer", "bencherdev", "beyondtrust", "bitovi", "blackduck-inc", "blazemeter", "boostsecurityio", "bridgecrewio", "broadsage", "browserstack", "bufbuild", "buildalon", "buildkite", "buildless", "bump-sh", "calibreapp", "caphyon", "carabiner-dev", "chainguard-dev", "charmbracelet", "chartdb", "checkmarx", "checkmarx-ts", "checkpointsw", "chromaui", "circleci-public", "cloud-maker-ai", "cloudflare", "cloudnation-nl", "cloudposse", "cloudsmith-io", "coalfire", "codacy", "codecov", "codefresh-io", "codequill-claim", "coder", "coderifts", "codesee-io", "codethreat", "composer", "configcat", "contrast-security-oss", "convisoappsec", "corellium", "coverallsapp", "crowdstrike", "cyberark", "cyberarmyid", "cypress-io", "dagger", "dapr", "dashlane", "databricks", "datadog", "datarobot-oss", "datreeio", "dbt-labs", "defensecode", "denoland", "dependabot", "depot", "designitetools", "determinatesystems", "dev-herald", "devcontainers", "devcyclehq", "developermetrics", "devops-actions", "diffblue", "digicert", "digitalocean", "directus", "docker", "dopplerhq", "drata", "ekline-io", "elide-dev", "elmahio", "embrace-io", "endorlabs", "erayaha", "erlef", "escape-technologies", "exlogare", "explore-dev", "expo", "facebook", "faros-ai", "fianulabs", "fiberplane", "flox", "fly-ci", "formspree", "fortify", "fossas", "fulcrumgenomics", "game-ci", "garden-io", "garnet-org", "genymobile", "getsentry", "git-for-windows", "gitguardian", "github", "gittools", "glueops", "go-task", "goauthentik", "gobeyondidentity", "gocardless", "godaddy", "goit", "golang", "google", "google-github-actions", "googleapis", "goreleaser", "graalvm", "gradle", "grafana", "green-coding-solutions", "gruntwork-io", "guardsquare", "hacktronai", "hashicorp", "hasura", "honeycombio", "hopinc", "hoverkraft-tech", "hubspot", "huggingface", "ibm", "inflectra", "infracost", "ionic-team", "issue-ops", "iterative", "jetbrains", "jfrog", "jreleaser", "jscrambler", "keeper-security", "kittycad", "koalalab-inc", "kosli-dev", "ksoclabs", "lacework", "lambdatest", "launchdarkly", "leanix", "legit-labs", "liblaber", "libum-llc", "lightlytics", "linear", "linear-b", "lingohub", "liquibase", "livecycle", "lob", "localstack", "lokalise", "mablhq", "matlab-actions", "membrowse", "mergifyio", "microsoft", "mobb-dev", "mobsf", "mockoon", "mondoohq", "montara-io", "nearform-actions", "netsparker", "newrelic", "nightfallai", "nitrictech", "nobl9", "nodesource", "northflank", "noteable-io", "nowsecure", "nrwl", "nuget", "nullify-platform", "octoberswimmer", "octokit", "octopusdeploy", "okteto", "olympix", "open-sauced", "opencontextinc", "openstatushq", "opentext", "opslevel", "optimal-ai", "oracle", "oracle-actions", "orcasecurity", "ossf", "oven-sh", "oxsecurity", "pachyderm", "pagerduty", "paloaltonetworks", "pangeacyber", "paperspace", "parasoft", "pdm-project", "perforce", "permission-protocol", "phrase", "phylum-dev", "pipery-dev", "pixee", "planetscale", "plivo", "polyapi", "ponicode", "port-labs", "portswigger", "portswigger-cloud", "postman-cs", "postmanlabs", "prefecthq", "prisma", "prismorsec", "probely", "projectdiscovery", "promptfoo", "prowler-cloud", "psalm", "psmodule", "pullpreview", "pulumi", "pushtodisplay", "pypa", "qensus-labs", "qualityclouds", "rainforestapp", "rapid7", "rapidapi", "readmeio", "red-gate", "redefinedev", "redhat-actions", "rematocorp", "renovatebot", "replicate", "restackio", "reversinglabs", "rigs-it", "rootlyhq", "ruby", "rubygems", "rust-lang", "saucelabs", "scalacenter", "scaleway", "scalr", "sec0ne", "securecodewarrior", "securesauce", "securestackco", "sematext", "serverless", "servicenow", "shipa-corp", "shipyard", "shopify", "shundor", "sideko-inc", "sigmacomputing", "signpath", "sigstore", "skill-bench", "slackapi", "snowflakedb", "snyk", "socketdev", "sodadata", "soldevelo", "solidify", "sonarsource", "sonatype", "sourcegraph", "sourcery-ai", "spacelift-io", "speakeasy-api", "spiceai", "sqlitecloud", "stackhawk", "stacklok", "stackql", "stackrox", "statsig-io", "step-security", "streetsidesoftware", "sturdy-dev", "supabase", "super-linter", "superfly", "swimmio", "synopsys-sig", "sysdiglabs", "tailscale", "taktile-org", "team-telnyx", "teamwork", "techpivot", "teleport-actions", "tenable", "terrateamio", "testlens-app", "testspace-com", "theneo-inc", "thomas-worm", "threatdetective", "tidbcloud", "towardsthecloud", "trufflesecurity", "trunk-io", "tryghost", "turbot", "twilio-labs", "typeform", "uffizzicloud", "unblocked", "useblacksmith", "vale-cli", "veertuinc", "veracode", "vercel", "verimatrix", "voidzero-dev", "warpbuilds", "wiz-sec-public", "workos", "wpengine", "xygeni", "yepcode", "yesolutions", "zaproxy", "zimperium", "zuplo"]

# Consider input package namespaces as verified
github_verified_partners contains input.packages[_].package_namespace

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"line": step.lines.uses,
	"job": job.id,
	"step": i,
	"details": step.uses,
	"purl": dep,
	"event_triggers": [event | event := workflow.events[j].name],
}) if {
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[i]
	dep := purl.parse_github_actions(step.uses, pkg.source_git_repo, pkg.source_git_ref)
	startswith(dep, "pkg:githubactions/")
	not regex.match(sprintf("pkg:githubactions/(%s)/", [concat("|", github_verified_partners)]), dep)
}

results contains poutine.finding(rule, pkg.purl, {
	"path": action.path,
	"line": step.lines.uses,
	"step": i,
	"details": step.uses,
	"purl": dep,
}) if {
	pkg := input.packages[_]
	action := pkg.github_actions_metadata[_]
	action.runs.using == "composite"
	step := action.runs.steps[i]
	dep := purl.parse_github_actions(step.uses, pkg.source_git_repo, pkg.source_git_ref)
	startswith(dep, "pkg:githubactions/")
	not regex.match(sprintf("pkg:githubactions/(%s)/", [concat("|", github_verified_partners)]), dep)
}
