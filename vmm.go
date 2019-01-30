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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// NewVMM creates a VMM object
func NewVMM(binary string, cfg firecracker.Config, metadata interface{}, fifoLogFile string) *VMM {
	return &VMM{
		binary:      binary,
		cfg:         cfg,
		metadata:    metadata,
		fifoLogFile: fifoLogFile,
	}
}

// VMM represents a virtual machine monitor
type VMM struct {
	ctx         context.Context
	binary      string
	cfg         firecracker.Config
	metadata    interface{}
	fifoLogFile string
	cleanupFns  []func() error
}

// Run a vmm with a given set of options
func (vmm *VMM) Run(ctx context.Context) error {
	logger := log.New()

	if vmm.cfg.Debug {
		logger.SetLevel(log.DebugLevel)
	}

	logWriter, err := vmm.handleFifos(createFifoFile)
	if err != nil {
		return err
	}
	defer vmm.Cleanup()
	vmm.cfg.FifoLogWriter = logWriter

	vmmCtx, vmmCancel := context.WithCancel(ctx)
	defer vmmCancel()

	machineOpts := []firecracker.Opt{
		firecracker.WithLogger(log.NewEntry(logger)),
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

	m, err := firecracker.NewMachine(vmmCtx, vmm.cfg, machineOpts...)
	if err != nil {
		return errors.Errorf("Failed creating machine: %s", err)
	}

	if vmm.metadata != nil {
		m.EnableMetadata(vmm.metadata)
	}

	if err := m.Start(vmmCtx); err != nil {
		return errors.Errorf("Failed to start machine: %v", err)
	}
	defer m.StopVMM()

	// wait for the VMM to exit
	if err := m.Wait(vmmCtx); err != nil {
		return errors.Errorf("Wait returned an error %s", err)
	}
	log.Printf("Start machine was happy")
	return nil
}

// handleFifos will see if any fifos need to be generated and if a fifo log
// file should be created.
func (vmm *VMM) handleFifos(createFifoFn func(string) (*os.File, error)) (io.Writer, error) {
	if len(vmm.fifoLogFile) > 0 && len(vmm.cfg.LogFifo) > 0 {
		return nil, errConflictingLogOpts
	}

	// these booleans are used to check whether or not the fifo queue or metrics
	// fifo queue needs to be generated. If any which need to be generated, then
	// we know we need to create a temporary directory. Otherwise, a temporary
	// directory does not need to be created.
	generateFifoFilename := len(vmm.cfg.LogFifo) == 0
	generateMetricFifoFilename := len(vmm.cfg.MetricsFifo) == 0
	var err error
	var fifo io.WriteCloser

	if len(vmm.fifoLogFile) > 0 {
		if fifo, err = createFifoFn(vmm.fifoLogFile); err != nil {
			return nil, errors.Wrap(err, errUnableToCreateFifoLogFile.Error())
		}
		vmm.addCleanupFn(func() error {
			return fifo.Close()
		})
	}

	if generateFifoFilename || generateMetricFifoFilename {
		dir, err := ioutil.TempDir(os.TempDir(), "fcfifo")
		if err != nil {
			return nil, errors.Errorf("Fail to create temporary directory: %v", err)
		}
		vmm.addCleanupFn(func() error {
			return os.RemoveAll(dir)
		})

		if generateFifoFilename {
			vmm.cfg.LogFifo = filepath.Join(dir, "fc_fifo")
		}
		if generateMetricFifoFilename {
			vmm.cfg.MetricsFifo = filepath.Join(dir, "fc_metrics_fifo")
		}
	}
	return fifo, nil
}

func (vmm *VMM) addCleanupFn(c func() error) {
	vmm.cleanupFns = append(vmm.cleanupFns, c)
}

// Cleanup removes temporarily used
func (vmm *VMM) Cleanup() {
	for _, closer := range vmm.cleanupFns {
		if err := closer(); err != nil {
			log.Error(err)
		}
	}
}

func createFifoFile(fifoPath string) (*os.File, error) {
	return os.OpenFile(fifoPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}
