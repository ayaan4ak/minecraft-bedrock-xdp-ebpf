package analytics

import (
	xdp "bedrock-xdp/xdp_utils"

	"github.com/cilium/ebpf"
)

var (
	collRef *ebpf.Collection
	// retained for potential future metrics (total blocks); not used in the
	// current analytics path but kept to avoid breaking other packages.
	counterMap *ebpf.Map
)

// GetBlockedCount prefers the live counter in block_counter (index 0). This
// reflects the number of *currently* blocked IPs because mitigation resets the
// counter to 0 whenever it flushes the map.  We keep the fallback to counting
// keys just in case the counter map cannot be found.
func GetBlockedCount() uint64 {
	if collRef == nil {
		return 0
	}
	if counterMap != nil {
		var key uint32 = 0
		var val uint64
		if err := counterMap.Lookup(&key, &val); err == nil {
			return val
		}
	}
	// Fallback: count keys directly.
	//m := xdp.GetMap("blocklist_map", collRef)
	return uint64(0)
}

func countMapEntries(m *ebpf.Map) int {
	if m == nil {
		return 0
	}
	var k uint32
	var v uint8
	iter := m.Iterate()
	cnt := 0
	for iter.Next(&k, &v) {
		cnt++
	}
	return cnt
}

// SetCollection caches the eBPF collection so GetBlockedCount can access maps.
func SetCollection(c *ebpf.Collection) {
	collRef = c
	counterMap = xdp.GetMap("block_counter", c)
}
