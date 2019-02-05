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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	// DefaultKernelOpts specifies what options to set on the kernel's command line
	// If you want it to boot faster you might want to consider the "ro" (read-only) and "nomodules" (disable module loading) options
	DefaultKernelOpts = "console=ttyS0 noapic reboot=k panic=1 pci=off rw"
	// DefaultCPUs specifies how many CPUs to enable by default
	DefaultCPUs int64 = 1
	// DefaultMemory specifies how much memory to reserve for the VM by default
	DefaultMemory int64 = 512
	// DefaultLogLevel specifies what the default log level is
	DefaultLogLevel = "INFO"
	// RuntimeDir specifies which directory firecracker "owns" and can store runtime data in
	RuntimeDir = "/var/lib/firecracker"
)

func newOptions() *options {
	return &options{}
}

// options represents parameters for running a VM
type options struct {
	Binary               string
	KernelImage          string
	KernelCmdLine        string
	RootDrivePath        string
	RootPartUUID         string
	AdditionalDrives     []string
	NICConfigs           []string
	VsockDevices         []string
	LogFifo              string
	LogLevel             string
	MetricsFifo          string
	EnableHyperthreading bool
	CPUCount             int64
	CPUTemplate          string
	Memory               int64
	Metadata             string
	FifoLogFile          string
	SocketPath           string
	Name                 string
	CopyFilesTo          []string
	CopyFilesFrom        []string
	cleanupFns           []func() error
}

// AddFlags adds the flags for these options to an arbitrary flagset
func (opts *options) AddFlags(fs *pflag.FlagSet) {
	// The kernel and attached devices
	fs.StringVar(&opts.KernelImage, "kernel", "./vmlinux", "Path to a uncompressed kernel image (vmlinux)")
	fs.StringVar(&opts.KernelCmdLine, "kernel-opts", DefaultKernelOpts, "Specify the VM kernel cmdline")
	fs.StringVar(&opts.RootDrivePath, "root-drive", "", "Path to a root disk image, either a ext4 formatted file or a physical device (required)")
	fs.StringVar(&opts.RootPartUUID, "root-partition", "", "Root partition UUID")
	fs.StringSliceVar(&opts.AdditionalDrives, "add-drive", nil, "Path to an additional drive, suffixed with :ro or :rw, can be specified multiple times")
	fs.StringSliceVar(&opts.NICConfigs, "add-network", nil, "Create a tap adapter on the host, connect it to ethX in the VM and possibly a bridge on the host. Specified as HOST_BRIDGE/HOST_TAP/GUEST_MAC, HOST_TAP/GUEST_MAC or just HOST_BRIDGE. Defaults to random HOST_TAP/GUEST_MAC. Can be specified multiple times.")
	fs.StringSliceVar(&opts.VsockDevices, "vsock-device", nil, "<Experimental> VSOCK interface, specified as PATH:CID, can be specified multiple times")
	// The machine specification
	fs.Int64VarP(&opts.CPUCount, "cpus", "c", DefaultCPUs, "Number of VM CPUs")
	fs.StringVar(&opts.CPUTemplate, "cpu-template", "", "Firecracker CPU Template (only C3 or T2 supported at the moment)")
	fs.Int64VarP(&opts.Memory, "memory", "m", DefaultMemory, "VM RAM memory, in MiB")
	// Runtime options
	fs.StringVar(&opts.Binary, "firecracker-binary", "", "Path to the firecracker binary, searches $PATH for it by default")
	fs.BoolVarP(&opts.EnableHyperthreading, "enable-hyperthreading", "t", true, "Enable CPU Hyperthreading")
	fs.StringVarP(&opts.SocketPath, "socket-path", "s", "", fmt.Sprintf("Path to use for firecracker socket, defaults to %s/{name}/firecracker.sock", RuntimeDir))
	fs.StringVar(&opts.Metadata, "metadata", "", "Metadata specified as raw JSON for MMDS")
	fs.StringVar(&opts.Name, "name", "", "Set a name for the VM, uses a randomly-generated 8 character string if unspecified")
	fs.StringSliceVar(&opts.CopyFilesTo, "copy-to", nil, "Copy files from the host to the guest in the form of HOST:GUEST (e.g. SSH keys, network config files, etc.), can be specified multiple times")
	fs.StringSliceVar(&opts.CopyFilesFrom, "copy-from", nil, "Copy files from the guest to the host in the form of HOST:GUEST (e.g. SSH keys, network config files, etc.), can be specified multiple times")
	// Logging options
	fs.StringVarP(&opts.FifoLogFile, "vmm-log-file", "l", "", fmt.Sprintf("Pipes the VMM fifo log to the specified file, mutually exclusive with --vmm-log-fifo, by default the file is written to %s/{name}/vmm.log", RuntimeDir))
	fs.StringVar(&opts.LogFifo, "vmm-log-fifo", "", "Specify a FIFO for firecracker logs, mutually exclusive with --vmm-log-file, by default the log file is used")
	fs.StringVar(&opts.MetricsFifo, "metrics-fifo", "", fmt.Sprintf("Specify a fifo for firecracker metrics, by default a new fifo is created in %s/{name}/metrics.fifo", RuntimeDir))
	fs.StringVar(&opts.LogLevel, "log-level", DefaultLogLevel, "Set the log level for both firectl and firecracker")
}

// Default sets the default values for these options
func (opts *options) Default() {
	if opts.Name == "" {
		randname := make([]byte, 4)
		rand.Read(randname)
		opts.Name = fmt.Sprintf("%x", randname)
	}
	if opts.SocketPath == "" {
		opts.SocketPath = opts.runtimeFilePath("firecracker.sock")
	}
	if opts.FifoLogFile == "" && opts.LogFifo == "" {
		// Both options need to be specified to firecracker for it to work.
		// This will make vmm.log be available only, because it has higher precedence.
		// But opts.LogFifo is always a mandatory value to firecracker
		opts.FifoLogFile = opts.runtimeFilePath("vmm.log")
		opts.LogFifo = opts.runtimeFilePath("vmm.fifo")
	}
	if opts.MetricsFifo == "" {
		opts.MetricsFifo = opts.runtimeFilePath("metrics.fifo")
	}
}

// Validate makes sure that current options are valid
func (opts *options) Validate() error {
	// TODO: Add an unit test for this
	errs := []error{}
	errs = append(errs, existingPathOrEmpty(opts.RootDrivePath, "root-drive"))
	errs = append(errs, requiredArg(opts.RootDrivePath, "root-drive"))
	errs = append(errs, existingPathOrEmpty(opts.KernelImage, "kernel"))
	errs = append(errs, requiredArg(opts.KernelImage, "kernel"))
	errs = append(errs, existingPathOrEmpty(opts.Binary, "firecracker-binary"))
	errs = append(errs, nonExistingPathOrEmpty(opts.SocketPath, "socket-path"))
	errs = append(errs, nonExistingPathOrEmpty(opts.FifoLogFile, "firecracker-log"))
	errs = append(errs, nonExistingPathOrEmpty(opts.MetricsFifo, "metrics-fifo"))
	errs = append(errs, nonExistingPathOrEmpty(opts.LogFifo, "vmm-log-fifo"))
	errs = append(errs, mustBePositiveInt(opts.CPUCount, "cpus"))
	errs = append(errs, mustBePositiveInt(opts.Memory, "memory"))

	// opts.FifoLogFile and opts.LogFifo are mutually exclusive, because LogFifo is ignored if FifoLogFile is set
	// But still both options need to be given internally to firecracker. So error if this was set incorrectly on the CLI
	// but allow our own defaults
	if len(opts.FifoLogFile) > 0 && len(opts.LogFifo) > 0 {
		if opts.FifoLogFile != opts.runtimeFilePath("vmm.log") && opts.LogFifo != opts.runtimeFilePath("vmm.fifo") {
			errs = append(errs, errConflictingLogOpts)
		}
	}
	return aggregateErrs(errs)
}

func (opts *options) runtimeFilePath(filename string) string {
	return filepath.Join(RuntimeDir, opts.Name, filename)
}

func requiredArg(val, argName string) error {
	if len(val) == 0 {
		return errors.Errorf("--%s is a required argument", argName)
	}
	return nil
}

func existingPathOrEmpty(path, argName string) error {
	if _, err := os.Stat(path); len(path) > 0 && err != nil {
		return errors.Wrap(err, fmt.Sprintf("--%s must point to an existing file", argName))
	}
	return nil
}

func nonExistingPathOrEmpty(path, argName string) error {
	if _, err := os.Stat(path); len(path) > 0 && !os.IsNotExist(err) {
		return errors.Wrap(err, fmt.Sprintf("--%s must not point to an existing file", argName))
	}
	return nil
}

func mustBePositiveInt(val int64, argName string) error {
	if val <= 0 {
		return errors.Errorf("--%s must be a number larger than 0", argName)
	}
	return nil
}

func aggregateErrs(errs []error) error {
	strs := []string{}
	for _, err := range errs {
		if err != nil {
			strs = append(strs, err.Error())
		}
	}
	if len(strs) > 0 {
		return errors.Errorf("%v", strs)
	}
	return nil
}

// ToVMM converts these  to a usable firecracker config
func (opts *options) ToVMM() (*VMM, error) {
	b, _ := json.Marshal(opts)
	log.Debugf("Merged Options struct: %s\n", b)

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
			HtEnabled:   opts.EnableHyperthreading,
			MemSizeMib:  opts.Memory,
		},
		Debug: strings.ToLower(opts.LogLevel) == "debug",
	}

	b, _ = json.Marshal(cfg)
	log.Debugf("Built Firecracker config: %s\n", b)

	return &VMM{
		binary:        opts.Binary,
		name:          opts.Name,
		rootDrivePath: opts.RootDrivePath,
		cfg:           cfg,
		metadata:      metadata,
		fifoLogFile:   opts.FifoLogFile,
		copyFilesTo:   opts.CopyFilesTo,
		copyFilesFrom: opts.CopyFilesFrom,
		cleanupFns:    opts.cleanupFns, // inherit the cleanup funcs that were registered here
	}, nil
}

func (opts *options) addCleanupFn(c func() error) {
	opts.cleanupFns = append(opts.cleanupFns, c)
}

func (opts *options) getNetwork(allowMDDS bool) ([]firecracker.NetworkInterface, error) {
	var NICs []firecracker.NetworkInterface
	if opts.NICConfigs != nil {
		for _, nic := range opts.NICConfigs {
			bridgeDev, tapDev, guestMacAddr, err := parseNICConfig(nic)
			if err != nil {
				return nil, err
			}
			if len(tapDev) == 0 { // default the tap interface name to fc{name}
				tapDev = fmt.Sprintf("fc%s", opts.Name)
			}
			if len(guestMacAddr) == 0 {
				parts := make([]byte, 5)
				rand.Read(parts)
				// always start the MAC addr with ea which implies internal & unicast
				guestMacAddr = fmt.Sprintf("ea:%02x:%02x:%02x:%02x:%02x", parts[0], parts[1], parts[2], parts[3], parts[4])
			}
			NICs = append(NICs, firecracker.NetworkInterface{
				MacAddress:  guestMacAddr,
				HostDevName: tapDev,
				AllowMDDS:   allowMDDS,
			})
			if len(bridgeDev) != 0 {
				// only require ip and brctl on host if a bridge was requested for the "easy mode"
				if err := createTAPAdapter(tapDev); err != nil {
					return nil, err
				}
				if err := connectTAPToBridge(tapDev, bridgeDev); err != nil {
					return nil, err
				}
			}
			// Do this nesting so that although tapDev is mutated every iteration, every tapDev cleanup func has the right param registered
			opts.addCleanupFn(func(devName string) func() error {
				return func() error {
					return executeCommand("ip", "link", "del", devName)
				}
			}(tapDev))
		}
	}
	return NICs, nil
}

func executeCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	out, err := cmd.CombinedOutput()
	cmdArgs := strings.Join(cmd.Args, " ")
	log.Debugf("Command %q returned %q\n", cmdArgs, out)
	if err != nil {
		return errors.Wrapf(err, "command %q exited with %q", cmdArgs, out)
	}
	return nil
}

func createTAPAdapter(tapName string) error {
	if err := executeCommand("ip", "tuntap", "add", "mode", "tap", tapName); err != nil {
		return err
	}
	return executeCommand("ip", "link", "set", tapName, "up")
}

func connectTAPToBridge(tapName, bridgeName string) error {
	return executeCommand("brctl", "addif", bridgeName, tapName)
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

// Given a string of the form BRIDGE/TAP/MAC, TAP/MAC or BRIDGE, return the appropriate values separately or an error
func parseNICConfig(str string) (string, string, string, error) {
	fields := strings.Split(str, "/")
	for _, field := range fields {
		if len(field) == 0 {
			return "", "", "", errInvalidNicConfig
		}
	}
	switch len(fields) {
	case 1:
		return fields[0], "", "", nil
	case 2:
		return "", fields[0], fields[1], nil
	case 3:
		return fields[0], fields[1], fields[2], nil
	}
	return "", "", "", errInvalidNicConfig
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
