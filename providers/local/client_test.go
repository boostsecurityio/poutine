package local

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_extractHostnameFromSSHURL(t *testing.T) {
	type args struct {
		sshURL string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "github",
			args: args{
				sshURL: "git@github.com:org/repo.git",
			},
			want: "github.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractHostnameFromSSHURL(tt.args.sshURL))
		})
	}
}
