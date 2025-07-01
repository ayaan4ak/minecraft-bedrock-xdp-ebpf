package xdp

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/cilium/ebpf"
)

const (
	objectFilename = "./xdp/xdp.o"
	programName    = "xdp_main_prog"
)

func Load(Interface string, Mode string) (error, *ebpf.Collection) {
	//Get context

	//Get XDPMode
	XdpMode := xdpMode(Mode)

	//Unlock memory
	err := UnlockMemory()
	if err != nil {
		return fmt.Errorf("error setting locked memory limit: %v", err), nil
	}

	//Reads file
	bytecode, err := ioutil.ReadFile(objectFilename)
	if err != nil {
		return err, nil
	}

	//Loads file
	collSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytecode))
	if err != nil {
		return err, nil
	}

	//get collection
	coll, err := ebpf.NewCollection(collSpec)
	if err != nil {
		return err, nil
	}

	//Get xdp prog
	loadedProg := coll.DetachProgram(programName)
	if loadedProg == nil {
		return fmt.Errorf("could not load program %s", programName), nil
	}
	defer loadedProg.Close()

	//Attach XDP prog
	if err = attachSocket(Interface, loadedProg, XdpMode); err != nil {
		return err, nil
	}
	return nil, coll
}
