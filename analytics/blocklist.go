package analytics

import (
	"github.com/cilium/ebpf"
)

var (
	counterMap *ebpf.Map
)

//Counter reset logic and Map Lookups should probably be reworked but what do you expect, this is open source.

func StartBlocklist(Collection *ebpf.Collection) {
	if Collection != nil {
		counterMap = Collection.Maps["block_counter"]
	}
}

// GetBlockedCount prefers the live counter in block_counter (index 0). This
// reflects the number of *currently* blocked IPs because mitigation resets the
// counter to 0 whenever it flushes the map.  We keep the fallback to counting
// keys just in case the counter map cannot be found.
func GetBlockedCount() uint64 {
	return getMapTotalCount(counterMap)
}
