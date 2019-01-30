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
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const (
	DefaultKernelOpts       = "ro console=ttyS0 noapic reboot=k panic=1 pci=off nomodules"
	DefaultCPUs       int64 = 1
	DefaultMemory     int64 = 512
	DefaultLogLevel         = "INFO"
)

func newOptions() *options {
	return &options{}
}

// options represents parameters for running a VM
type options struct {
	Binary           string
	KernelImage      string
	KernelCmdLine    string
	RootDrivePath    string
	RootPartUUID     string
	AdditionalDrives []string
	NicConfig        string
	VsockDevices     []string
	LogFifo          string
	LogLevel         string
	MetricsFifo      string
	DisableHt        bool
	CPUCount         int64
	CPUTemplate      string
	MemSz            int64
	Metadata         string
	FifoLogFile      string
	SocketPath       string
}

func (o *options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Binary, "firecracker-binary", "", "Path to firecracker binary. By default: Find it in $PATH")
	fs.StringVar(&o.KernelImage, "kernel", "./vmlinux", "Path to the kernel image")
	fs.StringVar(&o.KernelCmdLine, "kernel-opts", DefaultKernelOpts, "Kernel commandline")
	fs.StringVar(&o.RootDrivePath, "root-drive", "", "Path to root disk image. Required.")
	fs.StringVar(&o.RootPartUUID, "root-partition", "", "Root partition UUID")
	fs.StringSliceVar(&o.AdditionalDrives, "add-drive", nil, "Path to additional drive, suffixed with :ro or :rw, can be specified multiple times")
	fs.StringVar(&o.NicConfig, "tap-device", "", "NIC info, specified as DEVICE/MAC")
	fs.StringSliceVar(&o.VsockDevices, "vsock-device", nil, "Vsock interface, specified as PATH:CID. Multiple OK")
	fs.StringVar(&o.LogFifo, "vmm-log-fifo", "", "FIFO for firecracker logs")
	fs.StringVar(&o.LogLevel, "log-level", DefaultLogLevel, "VMM log level")
	fs.StringVar(&o.MetricsFifo, "metrics-fifo", "", "FIFO for firecracker metrics")
	fs.BoolVarP(&o.DisableHt, "disable-hyperthreading", "t", false, "Disable CPU Hyperthreading")
	fs.Int64VarP(&o.CPUCount, "ncpus", "c", DefaultCPUs, "Number of CPUs")
	fs.StringVar(&o.CPUTemplate, "cpu-template", "", "Firecracker CPU Template (C3 or T2)")
	fs.Int64VarP(&o.MemSz, "memory", "m", DefaultMemory, "VM memory, in MiB")
	fs.StringVar(&o.Metadata, "metadata", "", "Firecracker Metadata for MMDS (json)")
	fs.StringVarP(&o.FifoLogFile, "firecracker-log", "l", "", "Pipes the fifo contents to the specified file")
	fs.StringVarP(&o.SocketPath, "socket-path", "s", "", "Path to use for firecracker socket, defaults to a unique file in in the first existing directory from {$HOME, $TMPDIR, or /tmp}")
}

// ToVMM converts these  to a usable firecracker config
func (opts *options) ToVMM() (*VMM, error) {
	// validate metadata json
	var metadata interface{}
	if opts.Metadata != "" {
		if err := json.Unmarshal([]byte(opts.Metadata), &metadata); err != nil {
			return nil, errors.Wrap(err, errInvalidMetadata.Error())
		}
	}
	//setup NICs
	NICs, err := opts.getNetwork(metadata != nil)
	if err != nil {
		return nil, err
	}
	// BlockDevices
	blockDevices, err := opts.getBlockDevices()
	if err != nil {
		return nil, err
	}

	// vsocks
	vsocks, err := parseVsocks(opts.VsockDevices)
	if err != nil {
		return nil, err
	}

	logLevel, err := log.ParseLevel(opts.LogLevel)
	if err != nil {
		if opts.LogLevel != "" {
			return nil, err
		}
		logLevel = log.InfoLevel
	}

	if opts.SocketPath == "" {
		opts.SocketPath = getSocketPath()
	}

	cfg := firecracker.Config{
		// FifoLogWriter will be set based on opts.FifoLogFile later during runtime
		SocketPath:        opts.SocketPath,
		LogFifo:           opts.LogFifo,
		LogLevel:          opts.LogLevel,
		MetricsFifo:       opts.MetricsFifo,
		KernelImagePath:   opts.KernelImage,
		KernelArgs:        opts.KernelCmdLine,
		Drives:            blockDevices,
		NetworkInterfaces: NICs,
		VsockDevices:      vsocks,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:   opts.CPUCount,
			CPUTemplate: models.CPUTemplate(opts.CPUTemplate),
			HtEnabled:   !opts.DisableHt,
			MemSizeMib:  opts.MemSz,
		},
		Debug: strings.ToLower(opts.LogLevel) == "debug",
	}

	return NewVMM(opts.Binary, cfg, metadata, opts.FifoLogFile, logLevel), nil
}

func (opts *options) getNetwork(allowMDDS bool) ([]firecracker.NetworkInterface, error) {
	var NICs []firecracker.NetworkInterface
	if len(opts.NicConfig) > 0 {
		tapDev, tapMacAddr, err := parseNicConfig(opts.NicConfig)
		if err != nil {
			return nil, err
		}
		NICs = []firecracker.NetworkInterface{
			firecracker.NetworkInterface{
				MacAddress:  tapMacAddr,
				HostDevName: tapDev,
				AllowMDDS:   allowMDDS,
			},
		}
	}
	return NICs, nil
}

// constructs a list of drives from the options config
func (opts *options) getBlockDevices() ([]models.Drive, error) {
	blockDevices, err := parseBlockDevices(opts.AdditionalDrives)
	if err != nil {
		return nil, err
	}
	rootDrive := models.Drive{
		DriveID:      firecracker.String("1"),
		PathOnHost:   &opts.RootDrivePath,
		IsRootDevice: firecracker.Bool(true),
		IsReadOnly:   firecracker.Bool(false),
		Partuuid:     opts.RootPartUUID,
	}
	blockDevices = append(blockDevices, rootDrive)
	return blockDevices, nil
}

// given a []string in the form of path:suffix converts to []modesl.Drive
func parseBlockDevices(entries []string) ([]models.Drive, error) {
	devices := []models.Drive{}

	for i, entry := range entries {
		path := ""
		readOnly := true

		if strings.HasSuffix(entry, ":rw") {
			readOnly = false
			path = strings.TrimSuffix(entry, ":rw")
		} else if strings.HasSuffix(entry, ":ro") {
			path = strings.TrimSuffix(entry, ":ro")
		} else {
			return nil, errInvalidDriveSpecificationNoSuffix
		}

		if path == "" {
			return nil, errInvalidDriveSpecificationNoPath
		}

		if _, err := os.Stat(path); err != nil {
			return nil, err
		}

		e := models.Drive{
			// i + 2 represents the drive ID. We will reserve 1 for root.
			DriveID:      firecracker.String(strconv.Itoa(i + 2)),
			PathOnHost:   firecracker.String(path),
			IsReadOnly:   firecracker.Bool(readOnly),
			IsRootDevice: firecracker.Bool(false),
		}
		devices = append(devices, e)
	}
	return devices, nil
}

// Given a string of the form DEVICE/MACADDR, return the device name and the mac address, or an error
func parseNicConfig(cfg string) (string, string, error) {
	fields := strings.Split(cfg, "/")
	if len(fields) != 2 || len(fields[0]) == 0 || len(fields[1]) == 0 {
		return "", "", errInvalidNicConfig
	}
	return fields[0], fields[1], nil
}

// Given a list of string representations of vsock devices,
// return a corresponding slice of machine.VsockDevice objects
func parseVsocks(devices []string) ([]firecracker.VsockDevice, error) {
	var result []firecracker.VsockDevice
	for _, entry := range devices {
		fields := strings.Split(entry, ":")
		if len(fields) != 2 || len(fields[0]) == 0 || len(fields[1]) == 0 {
			return nil, errUnableToParseVsockDevices
		}
		cid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, errUnableToParseVsockCID
		}
		dev := firecracker.VsockDevice{
			Path: fields[0],
			CID:  uint32(cid),
		}
		result = append(result, dev)
	}
	return result, nil
}

// getSocketPath provides a randomized socket path by building a unique fielname
// and searching for the existance of directories {$HOME, os.TempDir()} and returning
// the path with the first directory joined with the unique filename. If we can't
// find a good path panics.
func getSocketPath() string {
	filename := strings.Join([]string{
		".firecracker.sock",
		strconv.Itoa(os.Getpid()),
		strconv.Itoa(rand.Intn(1000))},
		"-",
	)
	var dir string
	if d := os.Getenv("HOME"); checkExistsAndDir(d) {
		dir = d
	} else if checkExistsAndDir(os.TempDir()) {
		dir = os.TempDir()
	} else {
		panic("Unable to find a location for firecracker socket. 'It's not going to do any good to land on mars if we're stupid.' --Ray Bradbury")
	}

	return filepath.Join(dir, filename)
}

// checkExistsAndDir returns true if path exists and is a Dir
func checkExistsAndDir(path string) bool {
	// empty
	if path == "" {
		return false
	}
	// does it exist?
	if info, err := os.Stat(path); err == nil {
		// is it a directory?
		return info.IsDir()
	}
	return false
}
