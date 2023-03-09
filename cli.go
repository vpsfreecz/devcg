package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type action int

const (
	newProg     action = iota
	delProg     action = iota
	attachProg  action = iota
	detachProg  action = iota
	replaceProg action = iota
	setProg     action = iota
)

type options struct {
	action     action
	debug      bool
	cgroupPath string
	progName   string
	progPin    string
	linkPin    string
	newLinkPin string
	mode       Mode
	devices    DeviceList
}

const helpMessage = `
Usage: %s [options] <command> <arguments...>

Build and attach BPF programs to cgroupv2 devices controller.

Commands:
  set <prog pin> <cgroup path> <link pin> allow|deny <device...>    Create a program and attach it to a cgroup
  new <prog pin> allow|deny <device...>                  Create a program
  del <prog pin>                                         Delete a program
  attach <prog pin> <cgroup path> <link pin>             Attach existing program to cgroup
  detach <link pin>                                      Detach program from cgroup
  replace <link pin> <prog pin> [new link pin]           Replace program attached to a cgroup

<prog pin> is an absolute path to a file inside the BPF filesystem, usually located in /sys/fs/bpf.
As long as the pin file exists, the program is held in the kernel.

<link pin> is a file within the BPF filesystem representing BPF program attached to a cgroup.
When the link pin file is removed, the program is detached.

<cgroup path> is an absolute path to cgroup in a unified hierarchy, usually found in
/sys/fs/cgroup.

allow | deny determines whether the program will allow access only to the listed devices,
or if it will deny access to the listed devices and allow all others.

<device...> specify individual devices in the following format:

  basic | standard | <type>:<major>:<minor>:<access mask>

<type> is c for char and b for block devices. <major> and <minor> are devices numbers, * can be
used to match all major/minor numbers. <access mask> consists of r for read, w for write
and m for mknod access.

<device> basic is a shortcut to allow/deny access to /dev/null, /dev/zero, /dev/full, /dev/random
and /dev/urandom, as if they were enumerated on the command line.

<device> standard will allow/deny access to the basic devices, plus /dev/kmsg, /dev/tty,
/dev/console, /dev/ptmx, /dev/tty* and mknod for all devices.

Example use:

  mkdir /sys/fs/cgroup/my-cgroup
  
  %s set /sys/fs/bpf/my-program /sys/fs/cgroup/my-cgroup /sys/fs/bpf/my-program-on-my-cgroup allow basic

  %s set /sys/fs/bpf/my-program /sys/fs/cgroup/my-cgroup /sys/fs/bpf/my-program-on-my-cgroup allow c:1:3:rwm

Options:

`

func parseOptions() *options {
	opts := &options{}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), helpMessage, os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.BoolVar(
		&opts.debug,
		"debug",
		false,
		"Print program instructions",
	)

	flag.StringVar(
		&opts.progName,
		"name",
		"devcgprog",
		"Set BPF program name",
	)

	flag.Parse()

	args := flag.Args()

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: too few arguments\n")
		flag.Usage()
		return nil
	}

	cmd := args[0]
	var err error

	if cmd == "set" {
		err = parseSet(opts, args[1:])

	} else if cmd == "new" {
		err = parseNew(opts, args[1:])

	} else if cmd == "del" {
		err = parseDel(opts, args[1:])

	} else if cmd == "attach" {
		err = parseAttach(opts, args[1:])

	} else if cmd == "detach" {
		err = parseDetach(opts, args[1:])

	} else if cmd == "replace" {
		err = parseReplace(opts, args[1:])

	} else {
		err = fmt.Errorf("Unknown command %v", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		flag.Usage()
		return nil
	}

	return opts
}

func parseSet(opts *options, args []string) error {
	if len(args) < 5 {
		return fmt.Errorf("Error: too few arguments")
	}

	opts.action = setProg
	opts.progPin = args[0]
	opts.cgroupPath = args[1]
	opts.linkPin = args[2]

	if err := parseProgramMode(opts, args[3]); err != nil {
		return err
	}

	if err := parseDevices(opts, args[4:]); err != nil {
		return err
	}

	return nil
}

func parseNew(opts *options, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("Error: too few arguments")
	}

	opts.action = newProg
	opts.progPin = args[0]

	if err := parseProgramMode(opts, args[1]); err != nil {
		return err
	}

	if err := parseDevices(opts, args[2:]); err != nil {
		return err
	}

	return nil
}

func parseDel(opts *options, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("Invalid arguments")
	}

	opts.action = delProg
	opts.progPin = args[0]

	return nil
}

func parseAttach(opts *options, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("Invalid arguments")
	}

	opts.action = attachProg
	opts.progPin = args[0]
	opts.cgroupPath = args[1]
	opts.linkPin = args[2]

	return nil
}

func parseDetach(opts *options, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("Invalid arguments")
	}

	opts.action = detachProg
	opts.linkPin = args[0]

	return nil
}

func parseReplace(opts *options, args []string) error {
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("Invalid arguments")
	}

	opts.action = replaceProg
	opts.linkPin = args[0]
	opts.progPin = args[1]

	if len(args) > 2 {
		opts.newLinkPin = args[2]
	}

	return nil
}

func parseProgramMode(opts *options, mode string) error {
	if mode == "allow" {
		opts.mode = AllowList
	} else if mode == "deny" {
		opts.mode = DenyList
	} else {
		return fmt.Errorf("Error: invalid mode %v (expected allow/deny)", mode)
	}

	return nil
}

func parseDevices(opts *options, args []string) error {
	for _, v := range args {
		if v == "basic" {
			opts.devices = append(opts.devices, BasicDevices...)
			continue
		} else if v == "standard" {
			opts.devices = append(opts.devices, StandardDevices...)
			continue
		}

		dev, err := parseDevice(v)
		if err != nil {
			return fmt.Errorf("Invalid device %v: %v", v, err)
		}

		opts.devices = append(opts.devices, dev)
	}

	return nil
}

func parseDevice(s string) (DeviceSpec, error) {
	dev := DeviceSpec{}
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return dev, fmt.Errorf("bad format")
	}

	// Type
	if parts[0] == "c" || parts[0] == "char" {
		dev.DeviceType = CharDevice
	} else if parts[0] == "b" || parts[0] == "block" {
		dev.DeviceType = BlockDevice
	} else {
		return dev, fmt.Errorf("unknown device type %v", parts[0])
	}

	// Major
	if parts[1] == "*" {
		dev.Major = -1
	} else {
		major, err := strconv.Atoi(parts[1])
		if err != nil {
			return dev, fmt.Errorf("invalid major number %v", parts[1])
		}
		dev.Major = DeviceNumber(major)
	}

	// Minor
	if parts[2] == "*" {
		dev.Minor = -1
	} else {
		minor, err := strconv.Atoi(parts[2])
		if err != nil {
			return dev, fmt.Errorf("invalid minor number %v", parts[2])
		}
		dev.Minor = DeviceNumber(minor)
	}

	// Access mask
	for _, ch := range parts[3] {
		if ch == 'r' {
			dev.AccessMask |= ReadAccess
		} else if ch == 'w' {
			dev.AccessMask |= WriteAccess
		} else if ch == 'm' {
			dev.AccessMask |= MknodAccess
		} else {
			return dev, fmt.Errorf("invalid access mode %c", ch)
		}
	}

	return dev, nil
}
