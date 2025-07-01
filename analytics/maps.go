package analytics

import (
	"log"

	"github.com/cilium/ebpf"
)

func getMapTotalCount(bpfmap *ebpf.Map) uint64 {
	if bpfmap == nil {
		return 0
	}
	var totalKey uint32 = 0
	var totalCount uint64

	if err := bpfmap.Lookup(&totalKey, &totalCount); err != nil {
		log.Printf("\033[31m[ANALYTICS] \033[0mTotal Map Lookup error: \033[31m%s\033[0m\n", err)
		return 0
	}

	return totalCount
}

func resetPacketCountMap(packetCountMap *ebpf.Map) {
	if packetCountMap == nil {
		return
	}
	var key uint32
	var value uint64

	iter := packetCountMap.Iterate()
	for iter.Next(&key, &value) {
		var resetCount uint64 = 0
		_ = packetCountMap.Update(&key, &resetCount, ebpf.UpdateAny)
	}
}

func resetBitCountMap(packetCountMap *ebpf.Map) {
	if packetCountMap == nil {
		return
	}
	var key uint32
	var value uint64

	iter := packetCountMap.Iterate()
	for iter.Next(&key, &value) {
		var resetCount uint64 = 0
		_ = packetCountMap.Update(&key, &resetCount, ebpf.UpdateAny)
	}
}
