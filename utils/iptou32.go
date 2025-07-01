package utils

import (
	"encoding/binary"
	"net"
)

func IpToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0 // or handle the error appropriately (im not paid enough to do this)
	}
	return binary.BigEndian.Uint32(ip4)
}
