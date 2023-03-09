# devcgprog
devcgprog is a tool to configure cgroupv2 devices controller using BPF programs
from the command-line. It's a pure-Go implementation using the excellent
[cilium/ebpf](https://github.com/cilium/ebpf) library. No other compilers,
libraries or kernel sources are needed to use it.

## Requirements
- Mounted BPF filesystem, usually at `/sys/fs/bpf`
- Unified cgroup hierarchy
- Run as root

## Example
Allow access only to selected devices, e.g. only to `/dev/null`:

```bash
# devcgprog set /sys/fs/bpf/my-program \
                /sys/fs/cgroup/my-cgroup \
		/sys/fs/bpf/my-program-on-my-cgroup \
		allow c:1:3:rwm
```

The above command will generate a program, load it to the kernel and pin it
to `/sys/fs/bpf/my-program`. The pin is used to hold the program within the kernel.
The program is then attached to cgroup at `/sys/fs/cgroup/my-cgroup`. The link is
once again pinned in the BPF filesystem at `/sys/fs/bpf/my-program-on-my-cgroup`.

The program can then be detached as:

```bash
# devcgprog detach /sys/fs/bpf/my-program-on-my-cgroup
```

One program can be attached to multiple cgroups.

## Usage
```
Usage: devcgprog [options] <command> <arguments...>

Build and attach BPF programs to cgroupv2 devices controller.

Commands:
  set <prog pin> <cgroup path> allow|deny <device...>    Create a program and attach it to a cgroup
  new <prog pin> allow|deny <device...>                  Create a program
  del <prog pin>                                         Delete a program
  attach <prog pin> <cgroup path> <link pin>             Attach existing program to cgroup
  detach <link pin>                                      Detach program from cgroup

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

  devcgprog set /sys/fs/bpf/my-program /sys/fs/cgroup/my-cgroup allow basic

  devcgprog set /sys/fs/bpf/my-program /sys/fs/cgroup/my-cgroup allow c:1:3:rwm

Options:

  -debug
    	Print program instructions
  -name string
    	Set BPF program name (default "devcgprog")
```
