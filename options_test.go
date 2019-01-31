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
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
)

func TestToVMM(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "firectl-test-drive-path")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		tempFile.Close()
		os.Remove(tempFile.Name())
	}()
	cases := []struct {
		name        string
		opts        *options
		expectedErr func(error) (bool, error)
		outVMM      *VMM
	}{
		{
			name: "Invalid metadata",
			opts: &options{
				Metadata: "{ invalid:json",
			},
			expectedErr: func(e error) (bool, error) {
				return strings.HasPrefix(e.Error(), errInvalidMetadata.Error()), errInvalidMetadata
			},
			outVMM: nil,
		},
		{
			name: "Invalid network config",
			opts: &options{
				NICConfigs: []string{"a/"},
			},
			expectedErr: func(e error) (bool, error) {
				return e == errInvalidNicConfig, errInvalidNicConfig
			},
			outVMM: nil,
		},
		{
			name: "Invalid drives",
			opts: &options{
				NICConfigs:       []string{"a/b"},
				AdditionalDrives: []string{"/no-suffix"},
			},
			expectedErr: func(e error) (bool, error) {
				return e == errInvalidDriveSpecificationNoSuffix, errInvalidDriveSpecificationNoSuffix
			},
			outVMM: nil,
		},
		{
			name: "Invalid vsock addr",
			opts: &options{
				NICConfigs:       []string{"a/b"},
				AdditionalDrives: []string{tempFile.Name() + ":ro"},
				VsockDevices:     []string{"noCID"},
			},
			expectedErr: func(e error) (bool, error) {
				return e == errUnableToParseVsockDevices, errUnableToParseVsockDevices
			},
			outVMM: nil,
		},
		{
			name: "socket path provided",
			opts: &options{
				SocketPath:           "/some/path/here",
				EnableHyperthreading: true,
			},
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			outVMM: &VMM{
				cfg: firecracker.Config{
					SocketPath: "/some/path/here",
					Drives: []models.Drive{
						models.Drive{
							DriveID:      firecracker.String("1"),
							PathOnHost:   firecracker.String(""),
							IsRootDevice: firecracker.Bool(true),
							IsReadOnly:   firecracker.Bool(false),
						},
					},
					MachineCfg: models.MachineConfiguration{
						HtEnabled: true,
					},
				},
			},
		},
		{
			name: "Valid config",
			opts: &options{
				SocketPath:           "valid/path",
				EnableHyperthreading: true,
			},
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			outVMM: &VMM{
				cfg: firecracker.Config{
					SocketPath: "valid/path",
					Drives: []models.Drive{
						models.Drive{
							DriveID:      firecracker.String("1"),
							PathOnHost:   firecracker.String(""),
							IsRootDevice: firecracker.Bool(true),
							IsReadOnly:   firecracker.Bool(false),
						},
					},
					MachineCfg: models.MachineConfiguration{
						HtEnabled: true,
					},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vmm, err := c.opts.ToVMM()
			if ok, expected := c.expectedErr(err); !ok {
				t.Errorf("expected %s but got %s", expected, err)
			}
			if !reflect.DeepEqual(c.outVMM, vmm) {
				t.Errorf("expected %+v but got %+v", c.outVMM, vmm)
			}
		})

	}
}

func TestParseBlockDevices(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "firectl-test-drive-path")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		tempFile.Close()
		os.Remove(tempFile.Name())
	}()
	validDrive := models.Drive{
		DriveID:      firecracker.String("2"),
		PathOnHost:   firecracker.String(tempFile.Name()),
		IsReadOnly:   firecracker.Bool(false),
		IsRootDevice: firecracker.Bool(false),
	}
	cases := []struct {
		name        string
		in          []string
		outDrives   []models.Drive
		expectedErr func(error) bool
	}{
		{
			name:      "No drive suffix",
			in:        []string{"/path"},
			outDrives: nil,
			expectedErr: func(a error) bool {
				return a == errInvalidDriveSpecificationNoSuffix
			},
		},
		{
			name:      "No drive path",
			in:        []string{":rw"},
			outDrives: nil,
			expectedErr: func(a error) bool {
				return a == errInvalidDriveSpecificationNoPath
			},
		},
		{
			name:        "non-existant drive path",
			in:          []string{"/does/not/exist:ro"},
			outDrives:   nil,
			expectedErr: os.IsNotExist,
		},
		{
			name:      "valid drive path + suffix",
			in:        []string{tempFile.Name() + ":rw"},
			outDrives: []models.Drive{validDrive},
			expectedErr: func(a error) bool {
				return a == nil
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			drives, err := parseBlockDevices(c.in)
			if !reflect.DeepEqual(c.outDrives, drives) {
				t.Errorf("expected %v but got %v for %s",
					c.outDrives,
					drives,
					c.in)
			}
			if !c.expectedErr(err) {
				t.Errorf("did not get the expected err but received %s for %s",
					err,
					c.in)
			}
		})
	}
}

func TestParseNICConfigs(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		outBridge string
		outTap    string
		outMac    string
		outError  error
	}{
		{
			name:      "valid nic config, all",
			in:        "a/b/c",
			outBridge: "a",
			outTap:    "b",
			outMac:    "c",
			outError:  nil,
		},
		{
			name:      "valid nic config, tap and mac",
			in:        "a/b",
			outBridge: "",
			outTap:    "a",
			outMac:    "b",
			outError:  nil,
		},
		{
			name:      "valid nic config, bridge",
			in:        "ab",
			outBridge: "ab",
			outTap:    "",
			outMac:    "",
			outError:  nil,
		},
		{
			name:      "no macaddr",
			in:        "a/",
			outBridge: "",
			outTap:    "",
			outMac:    "",
			outError:  errInvalidNicConfig,
		},

		{
			name:      "empty nic config",
			in:        "",
			outBridge: "",
			outTap:    "",
			outMac:    "",
			outError:  errInvalidNicConfig,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bridge, tap, macaddr, err := parseNICConfig(c.in)
			if bridge != c.outBridge {
				t.Errorf("expected bridge %s but got %s for input %s",
					c.outBridge,
					bridge,
					c.in)
			}
			if tap != c.outTap {
				t.Errorf("expected tap device %s but got %s for input %s",
					c.outTap,
					tap,
					c.in)
			}
			if macaddr != c.outMac {
				t.Errorf("expected macaddr %s but got %s for input %s",
					c.outMac,
					macaddr,
					c.in)
			}
			if err != c.outError {
				t.Errorf("expected error %s but got %s for input %s",
					c.outError,
					err,
					c.in)
			}
		})
	}
}

func TestParseVsocks(t *testing.T) {
	cases := []struct {
		name        string
		in          []string
		outDevices  []firecracker.VsockDevice
		expectedErr func(a error) bool
	}{
		{
			name: "valid input",
			in:   []string{"a:3"},
			outDevices: []firecracker.VsockDevice{
				firecracker.VsockDevice{
					Path: "a",
					CID:  uint32(3),
				},
			},
			expectedErr: func(a error) bool {
				return a == nil
			},
		},
		{
			name:       "no CID",
			in:         []string{"a3:"},
			outDevices: nil,
			expectedErr: func(a error) bool {
				return a == errUnableToParseVsockDevices
			},
		},
		{
			name:       "empty vsock",
			in:         []string{""},
			outDevices: nil,
			expectedErr: func(a error) bool {
				return a == errUnableToParseVsockDevices
			},
		},
		{
			name:       "non-number CID",
			in:         []string{"a:b"},
			outDevices: nil,
			expectedErr: func(a error) bool {
				return a == errUnableToParseVsockCID
			},
		},
		{
			name:       "no separator",
			in:         []string{"ae"},
			outDevices: nil,
			expectedErr: func(a error) bool {
				return a == errUnableToParseVsockDevices
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			devices, err := parseVsocks(c.in)
			if !reflect.DeepEqual(devices, c.outDevices) {
				t.Errorf("expected %v but got %v for %s",
					c.outDevices,
					devices,
					c.in)
			}
			if !c.expectedErr(err) {
				t.Errorf("did not expect err: %s", err)
			}
		})
	}
}

func TestGetFirecrackerNetworkingConfig(t *testing.T) {
	cases := []struct {
		name        string
		opt         options
		expectedErr func(error) (bool, error)
		expectedNic []firecracker.NetworkInterface
	}{
		{
			name: "empty NicConfig",
			opt:  options{},
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			expectedNic: nil,
		},
		{
			name: "non-empty but invalid NICConfigs",
			opt: options{
				NICConfigs: []string{"ab/cd/ef/gh"},
			},
			expectedErr: func(e error) (bool, error) {
				return e == errInvalidNicConfig, errInvalidNicConfig
			},
			expectedNic: nil,
		},
		{
			name: "valid NICConfigs with mdds set to true",
			opt: options{
				NICConfigs: []string{"valid/things"},
				Metadata:   `{"foo": "bar"}`,
			},
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			expectedNic: []firecracker.NetworkInterface{
				firecracker.NetworkInterface{
					MacAddress:  "things",
					HostDevName: "valid",
					AllowMDDS:   true,
				},
			},
		},
		{
			name: "valid NICConfigs with mdds set to false",
			opt: options{
				NICConfigs: []string{"valid/things"},
			},
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			expectedNic: []firecracker.NetworkInterface{
				firecracker.NetworkInterface{
					MacAddress:  "things",
					HostDevName: "valid",
					AllowMDDS:   false,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nic, err := c.opt.getNetwork(c.opt.Metadata != "")
			if ok, expected := c.expectedErr(err); !ok {
				t.Errorf("expected %s but got %s", expected, err)
			}
			if !reflect.DeepEqual(nic, c.expectedNic) {
				t.Errorf("expected %v but got %v", c.expectedNic, nic)
			}
		})
	}
}

func TestGetBlockDevices(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "firectl-test-drive-path")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		tempFile.Close()
		os.Remove(tempFile.Name())
	}()
	cases := []struct {
		name           string
		opt            options
		expectedErr    func(e error) (bool, error)
		expectedDrives []models.Drive
	}{
		{
			name: "invalid AdditionalDrives value",
			opt: options{
				AdditionalDrives: []string{"ab"},
			},
			expectedErr: func(e error) (bool, error) {
				return e == errInvalidDriveSpecificationNoSuffix,
					errInvalidDriveSpecificationNoSuffix
			},
			expectedDrives: nil,
		},
		{
			name: "valid AdditionalDrives with valid Root drive",
			opt: options{
				AdditionalDrives: []string{tempFile.Name() + ":ro"},
				RootDrivePath:    tempFile.Name(),
				RootPartUUID:     "UUID",
			},
			expectedErr: func(e error) (bool, error) {
				return e == nil, nil
			},
			expectedDrives: []models.Drive{
				models.Drive{
					DriveID:      firecracker.String("2"),
					PathOnHost:   firecracker.String(tempFile.Name()),
					IsReadOnly:   firecracker.Bool(true),
					IsRootDevice: firecracker.Bool(false),
				},
				models.Drive{
					DriveID:      firecracker.String("1"),
					PathOnHost:   firecracker.String(tempFile.Name()),
					IsRootDevice: firecracker.Bool(true),
					IsReadOnly:   firecracker.Bool(false),
					Partuuid:     "UUID",
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			drives, err := c.opt.getBlockDevices()
			if ok, expected := c.expectedErr(err); !ok {
				t.Errorf("expected %s but got %s", expected, err)
			}
			if !reflect.DeepEqual(drives, c.expectedDrives) {
				t.Errorf("expected %v but got %v", c.expectedDrives, drives)
			}
		})
	}
}
