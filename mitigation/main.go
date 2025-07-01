package mitigation

import (
	"log"
	"net"
	"strconv"
	"time"

	"bedrock-xdp/config"
	"bedrock-xdp/mitigation/checks"
	"bedrock-xdp/utils"
	xdp "bedrock-xdp/xdp_utils"

	"github.com/cilium/ebpf"
)

// Start initialises mitigation-related BPF maps based on static configuration.
func Start(collection *ebpf.Collection) {
	// Populate AMP reflection port list
	PortMap := xdp.GetMap("port_map", collection)
	checks.UpdateAmpPorts(PortMap)

	// Load protected binds from config.yaml
	cfg, err := config.Load("./config.yaml")
	if err != nil {
		log.Printf("[MITIGATION] unable to load config: %v", err)
		return
	}

	protectedMap := xdp.GetMap("protected_map", collection)
	blocklistGlobal := xdp.GetMap("blocklist_global", collection)
	ratelimitLimit := xdp.GetMap("ratelimit_limit", collection)
	ratelimitBlock := xdp.GetMap("ratelimit_block", collection)
	ratelimitMap := xdp.GetMap("ratelimit_map", collection)
	blocklistMap := xdp.GetMap("blocklist_map", collection)
	blockCounter := xdp.GetMap("block_counter", collection)
	if protectedMap == nil {
		log.Printf("[MITIGATION] protected_map not found in BPF collection")
		return
	}

	// set blocklist global flag
	if blocklistGlobal != nil {
		var key uint32 = 0
		var value uint8 = 0
		if cfg.Blocklist.Enabled && cfg.Blocklist.Global {
			value = 1
		}
		_ = blocklistGlobal.Update(&key, &value, ebpf.UpdateAny)
	}

	// configure ratelimit values
	if ratelimitLimit != nil {
		var key uint32 = 0
		var limitVal uint32 = 0
		if cfg.Protection.Ratelimit {
			limitVal = uint32(cfg.Protection.Limit)
		}
		_ = ratelimitLimit.Update(&key, &limitVal, ebpf.UpdateAny)
	}
	if ratelimitBlock != nil {
		var key uint32 = 0
		var bl uint8 = 0
		if cfg.Protection.Block {
			bl = 1
		}
		_ = ratelimitBlock.Update(&key, &bl, ebpf.UpdateAny)
	}

	// ticker to clear connection_throttle every second
	if ratelimitMap != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			for range ticker.C {
				var ipKey uint32
				var val uint32
				iter := ratelimitMap.Iterate()
				for iter.Next(&ipKey, &val) {
					ratelimitMap.Delete(&ipKey)
				}
			}
		}()
	}

	// periodic blocklist flush according to config
	if cfg.Blocklist.Enabled && cfg.Blocklist.Blocktime > 0 && blocklistMap != nil {
		interval := time.Duration(cfg.Blocklist.Blocktime) * time.Second
		go func() {
			ticker := time.NewTicker(interval)
			for range ticker.C {
				var ip uint32
				var v uint8
				iter := blocklistMap.Iterate()
				for iter.Next(&ip, &v) {
					blocklistMap.Delete(&ip)
				}
				// Update counter to reflect current number of keys
				if blockCounter != nil {
					var k uint32 = 0
					// recount remaining keys in map (should be 0 unless new
					// IPs were added during the flush window)
					var rem uint64 = 0
					if blocklistMap != nil {
						var key uint32
						var val uint8
						it2 := blocklistMap.Iterate()
						for it2.Next(&key, &val) {
							rem++
						}
					}
					_ = blockCounter.Update(&k, &rem, ebpf.UpdateAny)
				}
			}
		}()
	}

	for _, bind := range cfg.Protection.Binds {
		host, portStr, err := net.SplitHostPort(bind)
		if err != nil {
			log.Printf("[MITIGATION] invalid bind entry %q: %v", bind, err)
			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			log.Printf("[MITIGATION] invalid port in bind %q: %v", bind, err)
			continue
		}

		var ipUint32 uint32
		if host == "0.0.0.0" {
			ipUint32 = 0
		} else {
			ip := net.ParseIP(host)
			if ip == nil {
				log.Printf("[MITIGATION] invalid IP in bind %q", bind)
				continue
			}
			ipUint32 = utils.IpToUint32(ip)
		}

		key := (uint64(ipUint32) << 16) | uint64(uint16(port))
		var value uint8 = 1
		if err := protectedMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			log.Printf("[MITIGATION] failed to insert %s into protected_map: %v", bind, err)
		}
	}
}
