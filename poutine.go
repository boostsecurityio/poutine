package main

import (
	"github.com/boostsecurityio/poutine/cmd"
)

var (
	version = "development"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.Commit = commit
	cmd.Version = version
	cmd.Date = date
	cmd.Execute()
}
