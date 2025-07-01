package utils

import (
	"net"
)

func IpToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0 // or handle the error appropriately (im not paid enough to do this)
	}
	return uint32(ip4[3])<<24 | uint32(ip4[2])<<16 | uint32(ip4[1])<<8 | uint32(ip4[0])
}
