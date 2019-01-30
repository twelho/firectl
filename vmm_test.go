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
	"os"
	"strings"
	"testing"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
)

func TestHandleFifos(t *testing.T) {
	validateTrue := func(VMM) bool { return true }
	cases := []struct {
		name           string
		vmm            VMM
		outWriterNil   bool
		expectedErr    func(error) (bool, error)
		numCleanupFns  int
		validate       func(VMM) bool
		createFifoFile func(string) (*os.File, error)
	}{
		{
			name: "both fifoLogFile and LogFifo set",
			vmm: VMM{
				fifoLogFile: "a",
				cfg: firecracker.Config{
					LogFifo: "b",
				},
			},
			outWriterNil: true,
			expectedErr: func(e error) (bool, error) {
				return e == errConflictingLogOpts, errConflictingLogOpts
			},
			numCleanupFns: 0,
			validate:      validateTrue,
		},
		{
			name: "set fifoLogFile causing createFifoFileLogs to fail",
			vmm: VMM{
				fifoLogFile: "fail-here",
			},
			createFifoFile: func(_ string) (*os.File, error) {
				return nil, errUnableToCreateFifoLogFile
			},
			outWriterNil: true,
			expectedErr: func(a error) (bool, error) {
				if a == nil {
					return false, errUnableToCreateFifoLogFile
				}
				return strings.HasPrefix(a.Error(),
						errUnableToCreateFifoLogFile.Error()),
					errUnableToCreateFifoLogFile
			},
			numCleanupFns: 0,
			validate:      validateTrue,
		},
		{
			name: "set LogFifo but not MetricsFifo",
			vmm: VMM{
				cfg: firecracker.Config{
					LogFifo: "testing",
				},
			},
			outWriterNil: true,
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			numCleanupFns: 1,
			validate: func(vmm VMM) bool {
				return strings.HasSuffix(vmm.cfg.MetricsFifo, "fc_metrics_fifo")
			},
		},
		{
			name: "set MetricsFifo but not LogFifo",
			vmm: VMM{
				cfg: firecracker.Config{
					MetricsFifo: "test",
				},
			},
			outWriterNil: true,
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			numCleanupFns: 1,
			validate: func(vmm VMM) bool {
				return strings.HasSuffix(vmm.cfg.LogFifo, "fc_fifo")
			},
		},
		{
			name: "set fifoLogFile with valid value",
			vmm: VMM{
				fifoLogFile: "value",
			},
			createFifoFile: createFifoFile,
			outWriterNil:   false,
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			numCleanupFns: 2,
			validate: func(vmm VMM) bool {
				// remove fcfifoLogFile that is created
				os.Remove(vmm.fifoLogFile)
				return strings.HasSuffix(vmm.cfg.LogFifo, "fc_fifo") &&
					strings.HasSuffix(vmm.cfg.MetricsFifo, "fc_metrics_fifo")
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, e := c.vmm.handleFifos(c.createFifoFile)
			if (w == nil && !c.outWriterNil) || (w != nil && c.outWriterNil) {
				t.Errorf("expected writer to be %v but writer was %v",
					c.outWriterNil,
					w == nil)
			}
			if ok, expected := c.expectedErr(e); !ok {
				t.Errorf("expected %s but got %s", expected, e)
			}
			if len(c.vmm.cleanupFns) != c.numCleanupFns {
				t.Errorf("expected to have %d cleanup fns but had %d",
					c.numCleanupFns,
					len(c.vmm.cleanupFns))
			}
			if !c.validate(c.vmm) {
				t.Errorf("VMM did not validate")
			}
			c.vmm.Cleanup()
		})
	}
}
