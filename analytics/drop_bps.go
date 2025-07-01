package analytics

import (
	"log"

	xdp "bedrock-xdp/xdp_utils"

	"github.com/cilium/ebpf"
)

var (
	udpDropBPS   *ebpf.Map // udp_drop_bps
	otherDropBPS *ebpf.Map // other_drop_bps
)

//Counter reset logic and Map Lookups should probably be reworked but what do you expect, this is open source.

func StartDroppedBPS(Collection *ebpf.Collection) {
	udpDropBPS = xdp.GetMap("udp_drop_bps", Collection)
	otherDropBPS = xdp.GetMap("other_drop_bps", Collection)
}

// ResetDropBPS clears dropped bit counters.
func ResetDropBPS() {
	var resetCount uint64 = 0
	var totalKey uint32 = 0

	if udpDropBPS != nil {
		udpDropBPS.Update(&totalKey, &resetCount, ebpf.UpdateAny)
	}
	if otherDropBPS != nil {
		otherDropBPS.Update(&totalKey, &resetCount, ebpf.UpdateAny)
	}

	resetByteCountMap(udpDropBPS)
	resetByteCountMap(otherDropBPS)
}

func resetByteCountMap(byteCountMap *ebpf.Map) {
	if byteCountMap == nil {
		return
	}
	var key uint32
	var resetCount uint64 = 0

	iter := byteCountMap.Iterate()
	for iter.Next(&key, &resetCount) {
		byteCountMap.Update(&key, &resetCount, ebpf.UpdateAny)
	}

	if err := iter.Err(); err != nil {
		log.Printf("Error resetting byte count map: %s\n", err)
	}
}

func GetTotalDroppedBPS(check string) uint64 {
	switch check {
	case "udp":
		return getMapTotalCount(udpDropBPS) / uint64(StatIntervalSec)
	case "other":
		return getMapTotalCount(otherDropBPS) / uint64(StatIntervalSec)
	default:
		return (getMapTotalCount(udpDropBPS) + getMapTotalCount(otherDropBPS)) / uint64(StatIntervalSec)
	}
}
