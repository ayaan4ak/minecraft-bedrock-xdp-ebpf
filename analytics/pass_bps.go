package analytics

import (
	xdp "bedrock-xdp/xdp_utils"

	"github.com/cilium/ebpf"
)

//Counter reset logic and Map Lookups should probably be reworked but what do you expect, this is open source.

var (
	udpBitMap   *ebpf.Map // udp_pass_bps
	otherBitMap *ebpf.Map // other_pass_bps
)

func StartBPS(Collection *ebpf.Collection) {
	udpBitMap = xdp.GetMap("udp_pass_bps", Collection)
	otherBitMap = xdp.GetMap("other_pass_bps", Collection)
}

// ResetPassBPS zeroes totals and per-IP buckets. Call once per interval **after**
// reading the stats so analytics never observes a just-reset value.
func ResetPassBPS() {
	var resetCount uint64 = 0
	var totalKey uint32 = 0

	if udpBitMap != nil {
		udpBitMap.Update(&totalKey, &resetCount, ebpf.UpdateAny)
	}
	if otherBitMap != nil {
		otherBitMap.Update(&totalKey, &resetCount, ebpf.UpdateAny)
	}

	resetBitCountMap(udpBitMap)
	resetBitCountMap(otherBitMap)
}

func GetTotalBPS(protocol string) uint64 {
	switch protocol {
	case "udp":
		return getMapTotalCount(udpBitMap) / uint64(StatIntervalSec)
	case "other":
		return getMapTotalCount(otherBitMap) / uint64(StatIntervalSec)
	default:
		return (getMapTotalCount(udpBitMap) + getMapTotalCount(otherBitMap)) / uint64(StatIntervalSec)
	}
}
