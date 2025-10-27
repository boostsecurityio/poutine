package sarif

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsValidGitURL(t *testing.T) {
	tests := []struct {
		name    string
		gitURL  string
		isValid bool
	}{
		{
			name:    "Valid HTTPS Git URL",
			gitURL:  "https://github.com/user/repo.git",
			isValid: true,
		},
		{
			name:    "Valid SSH Git URL",
			gitURL:  "ssh://git@bitbucket.org/user/repo.git",
			isValid: true,
		},
		{
			name:    "Valid Git URL without .git",
			gitURL:  "https://gitlab.com/user/repo",
			isValid: true,
		},
		{
			name:    "Invalid Git URL - missing scheme",
			gitURL:  "github.com/user/repo.git",
			isValid: false,
		},
		{
			name:    "Invalid Git URL - empty",
			gitURL:  "",
			isValid: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := IsValidGitURL(tt.gitURL)
			require.Equal(t, tt.isValid, isValid)
		})
	}
}
