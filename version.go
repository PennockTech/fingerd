// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"runtime"
)

// TODO: figure out if we want to bother with a makefile and git-derived version tagging, as used elsewhere

const fingerProgram = "fingerd"

var fingerVersion = "0.1.3"

// Pull the version derivation from whatever variables go into the makeup out
// into a function so that we can log it at startup.
func currentVersion() string {
	return fingerVersion
}

func version() {
	fmt.Printf("%s: Version %s\n", fingerProgram, currentVersion())
	fmt.Printf("%s: Golang: Runtime: %s\n", fingerProgram, runtime.Version())
}
