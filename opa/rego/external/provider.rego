package external.provider

advisories = {
	"gitlab": {"CVE-2024-2651": {
		"osv_id": "CVE-2024-2651",
		"published": "2022-05-24T19:01:50Z",
		"aliases": ["CVE-2021-32074"],
		"summary": "It was possible for an attacker to cause a denial of service using maliciously crafted markdown content.",
		"severity": [{
			"type": "CVSS_V3",
			"score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
		}],
		"cwe_ids": ["CWE-400"],
		"vulnerable_versions": [],
		"vulnerable_version_ranges": [">=0,<16.9.7"],
		"vulnerable_commit_shas": [],
	}},
	"github": {},
}
