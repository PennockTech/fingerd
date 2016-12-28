// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
)

// TODO: figure out if we want to bother with a makefile and git-derived version tagging, as used elsewhere

const fingerProgram = "fingerd"

var fingerVersion string = "0.1.0"

func version() {
	fmt.Printf("%s: Version %s\n", fingerProgram, fingerVersion)
}
