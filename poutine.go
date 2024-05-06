package main

import (
	"github.com/boostsecurityio/poutine/cmd"
)

var (
	Version = "development"
	Commit  = "none"
	Date    = "unknown"
)

func main() {
	cmd.Commit = Commit
	cmd.Version = Version
	cmd.Date = Date
	cmd.Execute()
}
