// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package main

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const (
	terminalProgram = "xterm"
	// consoleXterm indicates that the machine's console should be presented in an xterm
	consoleXterm = "xterm"
	// consoleStdio indicates that the machine's console should re-use the parent's stdio streams
	consoleStdio = "stdio"
	// consoleFile inddicates that the machine's console should be presented in files rather than stdout/stderr
	consoleFile = "file"
	// consoleNone indicates that the machine's console IO should be discarded
	consoleNone = "none"

	// executableMask is the mask needed to check whether or not a file's
	// permissions are executable.
	executableMask = 0111
)

func main() {
	opts := newOptions()
	opts.AddFlags(pflag.CommandLine)
	pflag.Parse()

	// if no flags just print help
	if pflag.NFlag() == 0 {
		pflag.Usage()
		os.Exit(0)
	}

	// convert options to an executable VMM
	opts.Default()
	if err := opts.Validate(); err != nil {
		log.Fatalf("validating the options failed: %v", err.Error())
	}
	vmm, err := opts.ToVMM()
	if err != nil {
		log.Fatalf("conversion to runtime config failed: %v", err.Error())
	}

	if err := vmm.Run(context.Background()); err != nil {
		log.Fatalf("running the vmm failed: %v", err.Error())
	}
}

// verifyFileIsExecutable verifies that the path given points to a binary that is executable
func verifyFileIsExecutable(binary string) error {
	finfo, err := os.Stat(binary)
	if os.IsNotExist(err) {
		return fmt.Errorf("Binary %q does not exist: %v", binary, err)
	}
	if err != nil {
		return fmt.Errorf("Failed to stat binary, %q: %v", binary, err)
	}

	if finfo.IsDir() {
		return fmt.Errorf("Binary, %q, is a directory", binary)
	} else if finfo.Mode()&executableMask == 0 {
		return fmt.Errorf("Binary, %q, is not executable. Check permissions of binary", binary)
	}
	return nil
}
