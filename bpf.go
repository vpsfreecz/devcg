package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type DeviceType int32

func (dt DeviceType) String() string {
	switch dt {
	case BlockDevice:
		return "b"
	case CharDevice:
		return "c"
	case AnyDevice:
		return "*"
	default:
		return "?"
	}
}

type AccessMask int32

func (am AccessMask) String() (ret string) {
	if (am & ReadAccess) == ReadAccess {
		ret += "r"
	} else {
		ret += "-"
	}

	if (am & WriteAccess) == WriteAccess {
		ret += "w"
	} else {
		ret += "-"
	}

	if (am & MknodAccess) == MknodAccess {
		ret += "m"
	} else {
		ret += "-"
	}

	return
}

type DeviceNumber int32

func (dn DeviceNumber) String() string {
	if dn == -1 {
		return "*"
	}

	return fmt.Sprintf("%d", dn)
}

type DeviceSpec struct {
	Name       string
	DeviceType DeviceType
	AccessMask AccessMask
	Major      DeviceNumber
	Minor      DeviceNumber
}

func (dev *DeviceSpec) Label() string {
	return fmt.Sprintf(
		"%s:%s:%s:%s",
		dev.DeviceType.String(),
		dev.Major.String(),
		dev.Minor.String(),
		dev.AccessMask.String(),
	)
}

func (dev *DeviceSpec) String() string {
	return dev.Label()
}

type DeviceList []DeviceSpec

type Mode int

func (m Mode) String() string {
	switch m {
	case AllowList:
		return "allow"
	case DenyList:
		return "deny"
	default:
		return "unknown"
	}
}

const (
	AllowList Mode = iota
	DenyList  Mode = iota

	MknodAccess AccessMask = 1
	ReadAccess  AccessMask = 2
	WriteAccess AccessMask = 4
	AllAccess   AccessMask = MknodAccess | ReadAccess | WriteAccess

	AnyDevice   DeviceType = 0
	BlockDevice DeviceType = 1
	CharDevice  DeviceType = 2

	U32Size = 4
)

var BasicDevices DeviceList = DeviceList{
	DeviceSpec{
		Name:       "/dev/null",
		DeviceType: CharDevice,
		Major:      1,
		Minor:      3,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/zero",
		DeviceType: CharDevice,
		Major:      1,
		Minor:      5,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/full",
		DeviceType: CharDevice,
		Major:      1,
		Minor:      7,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/random",
		DeviceType: CharDevice,
		Major:      1,
		Minor:      8,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/urandom",
		DeviceType: CharDevice,
		Major:      1,
		Minor:      9,
		AccessMask: AllAccess,
	},
}

var StandardDevices DeviceList = append(
	BasicDevices,
	DeviceSpec{
		Name:       "/dev/kmsg",
		DeviceType: CharDevice,
		Major:      1,
		Minor:      11,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/tty",
		DeviceType: CharDevice,
		Major:      5,
		Minor:      0,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/console",
		DeviceType: CharDevice,
		Major:      5,
		Minor:      1,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/ptmx",
		DeviceType: CharDevice,
		Major:      5,
		Minor:      2,
		AccessMask: AllAccess,
	},
	DeviceSpec{
		Name:       "/dev/tty*",
		DeviceType: CharDevice,
		Major:      136,
		Minor:      -1,
		AccessMask: AllAccess,
	},
	// Allow mknod for all devices
	DeviceSpec{
		DeviceType: BlockDevice,
		Major:      -1,
		Minor:      -1,
		AccessMask: MknodAccess,
	},
	DeviceSpec{
		DeviceType: CharDevice,
		Major:      -1,
		Minor:      -1,
		AccessMask: MknodAccess,
	},
)

func buildProgram(mode Mode, devices DeviceList) asm.Instructions {
	ins := initProgram()
	ins = addDevices(ins, mode, devices)
	ins = finishProgram(ins, mode)
	return ins
}

func initProgram() asm.Instructions {
	ins := asm.Instructions{
		// Device type to R2
		asm.LoadMem(asm.R2, asm.R1, U32Size*0, asm.Word).WithSource(asm.Comment("R2 = device type")),
		asm.And.Imm(asm.R2, 0xFFFF),

		// Access type to R3
		asm.LoadMem(asm.R3, asm.R1, U32Size*0, asm.Word).WithSource(asm.Comment("R3 = access type")),
		asm.RSh.Imm(asm.R3, 16),

		// Major number to R4
		asm.LoadMem(asm.R4, asm.R1, U32Size*1, asm.Word).WithSource(asm.Comment("R4 = major number")),

		// Minor number to R5
		asm.LoadMem(asm.R5, asm.R1, U32Size*2, asm.Word).WithSource(asm.Comment("R5 = minor number")),
	}

	return ins
}

func addDevices(ins asm.Instructions, mode Mode, devices DeviceList) asm.Instructions {
	deviceCount := len(devices)
	var lastDst string

	if mode == AllowList {
		lastDst = "deny"
	} else {
		lastDst = "allow"
	}

	for i, dev := range devices {
		isLast := i == deviceCount-1
		var jumpDst string

		if isLast {
			jumpDst = lastDst
		} else {
			jumpDst = devices[i+1].Label()
		}

		ins = append(ins, addDevice(dev, mode, jumpDst)...)
	}

	return ins
}

func addDevice(device DeviceSpec, mode Mode, jumpDst string) (ins asm.Instructions) {
	var matchDst string

	if mode == AllowList {
		matchDst = "allow"
	} else {
		matchDst = "deny"
	}

	if device.DeviceType != AnyDevice {
		ins = append(ins, asm.JNE.Imm(asm.R2, int32(device.DeviceType), jumpDst))
	}

	if device.Major != -1 {
		ins = append(ins, asm.JNE.Imm(asm.R4, int32(device.Major), jumpDst))
	}

	if device.Minor != -1 {
		ins = append(ins, asm.JNE.Imm(asm.R5, int32(device.Minor), jumpDst))
	}

	if device.AccessMask == AllAccess {
		ins = append(ins, asm.Ja.Label(matchDst))
	} else {
		ins = append(ins,
			asm.Mov.Reg32(asm.R1, asm.R3),
			asm.And.Imm32(asm.R1, int32(device.AccessMask)),
			asm.JEq.Reg(asm.R1, asm.R3, matchDst),
		)
	}

	ins[0] = ins[0].WithSymbol(device.Label())

	if device.Name != "" {
		ins[0] = ins[0].WithSource(asm.Comment(device.Name))
	}

	return
}

func addAllowRule(ins asm.Instructions) asm.Instructions {
	ins = append(ins,
		asm.LoadImm(asm.R0, 1, asm.DWord).WithSymbol("allow"),
		asm.Return(),
	)

	return ins
}

func addDenyRule(ins asm.Instructions) asm.Instructions {
	ins = append(ins,
		asm.LoadImm(asm.R0, 0, asm.DWord).WithSymbol("deny"),
		asm.Return(),
	)

	return ins
}

func finishProgram(ins asm.Instructions, mode Mode) asm.Instructions {
	if mode == AllowList {
		ins = addDenyRule(ins)
		ins = addAllowRule(ins)
	} else {
		ins = addAllowRule(ins)
		ins = addDenyRule(ins)
	}

	return ins
}

func loadProgram(name string, ins asm.Instructions, progPin string) (*ebpf.Program, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         name,
		Type:         ebpf.CGroupDevice,
		Instructions: ins,
		License:      "GPL",
	})

	if err != nil {
		return nil, fmt.Errorf("Unable to create program: %v", err)
	}

	if err := prog.Pin(progPin); err != nil {
		return nil, fmt.Errorf("Unable to pin program: %v", err)
	}

	return prog, nil
}

func loadPinnedProgram(progPin string) (*ebpf.Program, error) {
	return ebpf.LoadPinnedProgram(progPin, nil)
}

func attachProgram(prog *ebpf.Program, progPin string, cgroupPath string, linkPin string) error {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupDevice,
		Program: prog,
	})

	if err != nil {
		return fmt.Errorf("Unable to attach program to %s: %v", cgroupPath, err)
	}

	defer l.Close()

	if err := l.Pin(linkPin); err != nil {
		return fmt.Errorf("Unable to pin link: %v", err)
	}

	return nil
}

func loadPinnedLink(linkPin string) (link.Link, error) {
	return link.LoadPinnedLink(linkPin, nil)
}
