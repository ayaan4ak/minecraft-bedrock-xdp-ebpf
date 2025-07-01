package analytics

import (
	"time"

	"github.com/cilium/ebpf"
)

// StartBlockCounterReset zeros the block_counter map every <blocktime> seconds
// so it stays in sync with the flush happening in mitigation.
// It does NOT touch blocklist_map itself.
func StartBlockCounterReset(coll *ebpf.Collection, blocktime int) {
	if blocktime <= 0 {
		return
	}

	// Use the collection's in-place map handle so we can write immediately
	counter := coll.Maps["block_counter"]
	if counter == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(blocktime) * time.Second)
		for range ticker.C {
			var idx uint32 = 0
			var zero uint64 = 0
			_ = counter.Update(&idx, &zero, ebpf.UpdateAny)
		}
	}()
}
