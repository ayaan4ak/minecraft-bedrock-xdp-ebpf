package analytics

import (
	xdp "bedrock-xdp/xdp_utils"

	"github.com/cilium/ebpf"
)

var (
	udpDropPPS   *ebpf.Map // udp_drop_pps
	otherDropPPS *ebpf.Map // other_drop_pps
)

//Counter reset logic and Map Lookups should probably be reworked but what do you expect, this is open source.

func StartDroppedPPS(Collection *ebpf.Collection) {
	udpDropPPS = xdp.GetMap("udp_drop_pps", Collection)
	otherDropPPS = xdp.GetMap("other_drop_pps", Collection)
}

// ResetDropPPS clears dropped packet counters.
func ResetDropPPS() {
	var resetCount uint64 = 0
	var totalKey uint32 = 0

	if udpDropPPS != nil {
		udpDropPPS.Update(&totalKey, &resetCount, ebpf.UpdateAny)
	}
	if otherDropPPS != nil {
		otherDropPPS.Update(&totalKey, &resetCount, ebpf.UpdateAny)
	}

	resetPacketCountMap(udpDropPPS)
	resetPacketCountMap(otherDropPPS)
}

func GetTotalDroppedPPS(check string) uint64 {
	switch check {
	case "udp":
		return getMapTotalCount(udpDropPPS) / uint64(StatIntervalSec)
	case "other":
		return getMapTotalCount(otherDropPPS) / uint64(StatIntervalSec)
	default:
		return (getMapTotalCount(udpDropPPS) + getMapTotalCount(otherDropPPS)) / uint64(StatIntervalSec)
	}
}
