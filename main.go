package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	opts := parseOptions()

	if opts == nil {
		return
	}

	var err error

	switch opts.action {
	case setProg:
		err = runSetProg(opts)
	case newProg:
		err = runNewProg(opts)
	case delProg:
		err = runDelProg(opts)
	case attachProg:
		err = runAttachProg(opts)
	case detachProg:
		err = runDetachProg(opts)
	default:
		err = fmt.Errorf("Unknown action %v", opts.action)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func runSetProg(opts *options) error {
	ins := buildProgram(opts.mode, opts.devices)

	if opts.debug {
		fmt.Printf("%v\n", ins)
	}

	prog, err := loadProgram(opts.progName, ins, opts.progPin)

	if err != nil {
		return err
	}

	defer prog.Close()

	if err := attachProgram(prog, opts.progPin, opts.cgroupPath, opts.linkPin); err != nil {
		return err
	}

	return nil
}

func runNewProg(opts *options) error {
	ins := buildProgram(opts.mode, opts.devices)

	if opts.debug {
		fmt.Printf("%v\n", ins)
	}

	prog, err := loadProgram(opts.progName, ins, opts.progPin)

	if err != nil {
		return err
	}

	defer prog.Close()

	return nil
}

func runDelProg(opts *options) error {
	return os.Remove(opts.progPin)
}

func runAttachProg(opts *options) error {
	prog, err := loadPinnedProgram(opts.progPin)

	if err != nil {
		return err
	}

	defer prog.Close()

	if err := attachProgram(prog, opts.progPin, opts.cgroupPath, opts.linkPin); err != nil {
		return err
	}

	return nil
}

func runDetachProg(opts *options) error {
	return os.Remove(opts.linkPin)
}
