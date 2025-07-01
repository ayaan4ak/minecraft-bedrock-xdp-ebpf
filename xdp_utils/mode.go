package xdp

import "log"

func xdpMode(Mode string) (XdpMode int) {

	XdpMode = 0

	switch Mode {
	case "AUTO":
		XdpMode = 0
	case "SKB":
		XdpMode = (1 << 1)
	case "DRV":
		XdpMode = (1 << 2)
	case "NIC":
		XdpMode = (1 << 3)
	default:
		XdpMode = 0
		log.Printf("\033[36m[XDP UTILS] \033[0mFailed to fetch \033[36mxdpmode\033[0m from Config, defaulting to \033[36mAUTO\033[0m")
	}
	return XdpMode
}
