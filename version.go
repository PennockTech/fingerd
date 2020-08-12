// Copyright © 2016,2019,2020 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"runtime"
)

const fingerProgram = "fingerd"

var fingerVersion = "0.2.2-dev"

// Pull the version derivation from whatever variables go into the makeup out
// into a function so that we can log it at startup.
func currentVersion() string {
	return fingerVersion
}

func goVersion() string {
	return runtime.Version()
}

func version() {
	fmt.Printf("%s: Version %s\n", fingerProgram, currentVersion())
	fmt.Printf("%s: Golang: Runtime: %s\n", fingerProgram, goVersion())
}
