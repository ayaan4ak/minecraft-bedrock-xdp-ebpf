package main

import (
	"bedrock-xdp/analytics"
	"bedrock-xdp/config"
	"bedrock-xdp/mitigation"
	xdp "bedrock-xdp/xdp_utils"
	"log"
	"os"
)

func main() {

	log.Printf("\033[36m[BEDROCK-XDP] \033[0mStarting v1.1.0 \033[36m(By:\033[36m@upioti \033[0m- \033[36mhttps://papyrus.vip/\033[36m)\033[0m")

	if !fileExists("./config.yaml") {
		config.Init()
		log.Printf("\033[36m[BEDROCK-XDP] \033[0mCreated Main Config \033[36m(config.yaml)\033[0m")
		log.Fatalf("\033[36m[BEDROCK-XDP] \033[0mPlease configure the program and run again.")

	}
	cfg, err := config.Load("./config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	log.Printf("\033[36m[BEDROCK-XDP] \033[0mLoaded Config \033[36m(%+v)\033[0m\n", cfg)
	log.Printf("\033[36m[BEDROCK-XDP] \033[0mStarting Mitigation...")

	err, coll := xdp.Load(cfg.Network.Interface, cfg.Network.XdpMode)
	if err != nil {
		log.Fatalf("%v", err)
	}

	go mitigation.Start(coll)

	// start analytics (stats + optional blocklist maintenance)
	interval := 5
	if cfg.Stats.Interval > 0 {
		interval = cfg.Stats.Interval
	}

	if cfg.Blocklist.Enabled && cfg.Blocklist.Blocktime > 0 {
		go analytics.StartBlockCounterReset(coll, cfg.Blocklist.Blocktime)
	}

	go analytics.Init(coll, cfg.Prometheus.Bind, cfg.Prometheus.Enabled, cfg.Prometheus.Pop, interval)

	select {}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
