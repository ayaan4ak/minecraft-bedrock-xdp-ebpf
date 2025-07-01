package xdp

import (
	"github.com/cilium/ebpf"
)

func GetMap(name string, Coll *ebpf.Collection) *ebpf.Map {

	bpfmap := Coll.DetachMap(name)
	return bpfmap
}
