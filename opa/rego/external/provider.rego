package external.provider

advisories = {
	"gitlab": {"CVE-2024-2651": {
		"osv_id": "CVE-2024-2651",
		"published": "2024-05-14T00:00:00Z",
		"aliases": [],
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
	"github": {"CVE-2024-4985": {
		"osv_id": "CVE-2024-4985",
		"published": "2024-05-20T00:00:00Z",
		"aliases": [],
		"summary": "It was possible for an attacker to cause a denial of service using maliciously crafted markdown content.",
		"severity": [{
			"type": "CVSS_V4",
			"score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:U/V:C/RE:M/U:Red",
		}],
		"cwe_ids": ["CWE-303"],
		"vulnerable_versions": [],
		"vulnerable_version_ranges": ["<3.9.15","<3.10.12","<3.11.10","<3.12.4"],
		"vulnerable_commit_shas": [],
	}},
}
