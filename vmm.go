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

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	log "github.com/sirupsen/logrus"
)

// NewVMM creates a VMM object
func NewVMM(binary string, cfg *firecracker.Config, metadata interface{}) *VMM {
	return &VMM{
		binary:   binary,
		cfg:      cfg,
		metadata: metadata,
		logger:   log.New(),
	}
}

// VMM represents a virtual machine monitor
type VMM struct {
	ctx      context.Context
	binary   string
	cfg      *firecracker.Config
	metadata interface{}
	logger   *log.Logger
}

// Run a vmm with a given set of options
func (vmm *VMM) Run(ctx context.Context) error {
	if vmm.cfg.Debug {
		vmm.logger.SetLevel(log.DebugLevel)
	}

	vmmCtx, vmmCancel := context.WithCancel(ctx)
	defer vmmCancel()

	machineOpts := []firecracker.Opt{
		firecracker.WithLogger(log.NewEntry(vmm.logger)),
	}

	if len(vmm.binary) != 0 {
		if err := verifyFileIsExecutable(vmm.binary); err != nil {
			return err
		}

		cmd := firecracker.VMCommandBuilder{}.
			WithBin(vmm.binary).
			WithSocketPath(vmm.cfg.SocketPath).
			WithStdin(os.Stdin).
			WithStdout(os.Stdout).
			WithStderr(os.Stderr).
			Build(ctx)

		machineOpts = append(machineOpts, firecracker.WithProcessRunner(cmd))
	}

	m, err := firecracker.NewMachine(vmmCtx, *vmm.cfg, machineOpts...)
	if err != nil {
		return fmt.Errorf("Failed creating machine: %s", err)
	}

	if vmm.metadata != nil {
		m.EnableMetadata(vmm.metadata)
	}

	if err := m.Start(vmmCtx); err != nil {
		return fmt.Errorf("Failed to start machine: %v", err)
	}
	defer m.StopVMM()

	// wait for the VMM to exit
	if err := m.Wait(vmmCtx); err != nil {
		return fmt.Errorf("Wait returned an error %s", err)
	}
	log.Printf("Start machine was happy")
	return nil
}
