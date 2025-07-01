package analytics

import (
	"bedrock-xdp/utils"
	"log"
	"math"
	"time"

	"github.com/cilium/ebpf"
)

// Init spawns routines to collect and expose BPF statistics.
// Metrics have been simplified to reflect the new map layout: UDP and OTHER passes, and UDP drops.
func Init(Collection *ebpf.Collection, bind string, prometheus bool, pop string, intervalSec int) {

	if intervalSec > 0 {
		StatIntervalSec = intervalSec
	}

	//Traffic Analytics and Packet Counter logic should probably be reworked but what do you expect, this is open source.

	var (
		// Passed traffic
		udp_pps   uint64
		udp_bps   float64
		other_pps uint64
		other_bps float64

		// Dropped traffic
		dropudp_pps   uint64
		dropudp_bps   float64
		dropother_pps uint64
		dropother_bps float64

		// Display aggregates
		pass_pps uint64
		pass_bps float64
		drop_pps uint64
		drop_bps float64
	)

	log.Printf("\033[36m[BEDROCK-XDP] \033[0mStarting Analytics...")
	StartBlocklist(Collection)

	// initialise map references only (no goroutine resets)
	StartBPS(Collection)
	StartPPS(Collection)
	StartDroppedBPS(Collection)
	StartDroppedPPS(Collection)

	if prometheus {
		StartPrometheus(bind)
	}

	ticker := time.NewTicker(1 * time.Second)
	counterTick := 0
	for range ticker.C {

		// Gather pass statistics
		udp_pps = GetTotalPPS("udp")
		udp_bps = float64(GetTotalBPS("udp"))
		other_pps = GetTotalPPS("other")
		other_bps = float64(GetTotalBPS("other"))

		// Gather drop statistics
		dropudp_pps = GetTotalDroppedPPS("udp")
		dropudp_bps = float64(GetTotalDroppedBPS("udp"))
		dropother_pps = GetTotalDroppedPPS("other")
		dropother_bps = float64(GetTotalDroppedBPS("other"))

		pass_pps = udp_pps + other_pps
		pass_bps = math.Ceil(float64(udp_bps+other_bps)/10000.0) / 100.0

		drop_pps = dropudp_pps + dropother_pps
		drop_bps = math.Ceil(float64(dropudp_bps+dropother_bps)/10000.0) / 100.0

		if prometheus {
			// Pass metrics
			passedPackets.WithLabelValues(pop, "UDP").Set(float64(udp_pps))
			passedBits.WithLabelValues(pop, "UDP").Set(udp_bps)
			passedPackets.WithLabelValues(pop, "OTHER").Set(float64(other_pps))
			passedBits.WithLabelValues(pop, "OTHER").Set(other_bps)

			// Drop metrics
			droppedPackets.WithLabelValues(pop, "UDP").Set(float64(dropudp_pps))
			droppedBits.WithLabelValues(pop, "UDP").Set(dropudp_bps)
			droppedPackets.WithLabelValues(pop, "OTHER").Set(float64(dropother_pps))
			droppedBits.WithLabelValues(pop, "OTHER").Set(dropother_bps)

			// Blocked IPs
			blockedIPs.WithLabelValues(pop).Set(float64(GetBlockedCount()))
		}

		// Console output
		log.Printf("\033c")
		log.Printf("\033[36m[BEDROCK-XDP] \033[0mRunning v1.1.0 \033[36m(By:\033[36m@upioti \033[0m- \033[36mhttps://papyrus.vip/\033[36m)\033[0m")
		log.Printf("\n")
		log.Printf("\033[36m[ANALYTICS] \033[0mPassed traffic statistics:\033[0m\n")
		log.Printf("\033[36m[ANALYTICS] \033[0mPassed Packets: \033[36m%s/s\033[0m\n", utils.FormatWithCommas(pass_pps))
		log.Printf("\033[36m[ANALYTICS] \033[0mPassed Bits: \033[36m%.2f mbit/s\033[0m\n", pass_bps)
		log.Printf("\n")
		log.Printf("\033[36m[ANALYTICS] \033[0mDropped traffic statistics:\033[0m\n")
		log.Printf("\033[36m[ANALYTICS] \033[0mDropped Packets: \033[36m%s/s\033[0m\n", utils.FormatWithCommas(drop_pps))
		log.Printf("\033[36m[ANALYTICS] \033[0mDropped Bits: \033[36m%.2f mbit/s\033[0m\n", drop_bps)

		// Console print blocked IPs
		bcVal2 := GetBlockedCount()
		log.Printf("\n")
		log.Printf("\033[36m[ANALYTICS] \033[0mBlocked IPs: \033[36m%d\033[0m\n", bcVal2)

		// After producing metrics, reset counters for next window if we've
		// reached StatIntervalSec seconds since last reset.
		counterTick++
		if counterTick >= StatIntervalSec {
			ResetPassBPS()
			ResetPassPPS()
			ResetDropBPS()
			ResetDropPPS()
			counterTick = 0
		}
	}
}
