package scm_domain

import "testing"

var tests = map[string]struct {
	input    string
	expected string
}{
	"strip https": {
		input:    "https://scm.com",
		expected: "scm.com",
	},
	"strip http": {
		input:    "http://example.scm.com",
		expected: "example.scm.com",
	},
	"ignore": {
		input:    "scm.com",
		expected: "scm.com",
	},
	"empty": {
		input:    "",
		expected: "",
	},
	"trailing slash": {
		input:    "https://scm.com/",
		expected: "scm.com",
	},
	"sub path": {
		input:    "https://scm.com/sub/domain",
		expected: "scm.com/sub/domain",
	},
}

func TestScmBaseDomain(t *testing.T) {
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var d ScmBaseDomain
			err := d.Set(test.input)
			if err != nil {
				t.Fatal(err)
			}
			s := d.String()
			if s != test.expected {
				t.Errorf("expected %s, got %s", test.expected, s)
			}
		})
	}
}

func TestScmBaseDomainNil(t *testing.T) {
	var d ScmBaseDomain
	if d.String() != "" {
		t.Error("expected default value of to be \"\"")
	}
}
