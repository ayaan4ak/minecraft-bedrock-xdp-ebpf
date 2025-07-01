package xdp

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func attachSocket(ifaceName string, loadedProg *ebpf.Program, attachMode int) error {
	// Lookup interface by given name, we need to extract iface index
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("\033[31m[XDP SOCKET] \033[0mInterface Error: \033[31m%v\033[0m", err)
	}

	// Attach program
	if err := netlink.LinkSetXdpFdWithFlags(link, loadedProg.FD(), int(attachMode)); err != nil {
		return fmt.Errorf("\033[31m[XDP SOCKET] \033[0mAttaching Program Failed: \033[31m%v\033[0m", err)
	}

	return nil
}
