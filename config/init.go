package config

import (
	"log"
	"os"
)

func Init() {
	configPath := "config.yaml"

	// Manually construct the YAML content with inline comments
	yamlContent := `
#-----------------------------------------------------------------
# Welcome to Bedrock XDP filter 1.0.0 
# By @upioti (DC) - https://upioti.com/
#
# Check out https://papyrus.vip/ for enterprise DDoS protection
# Or https://arvor.is/ to secure your server at a budget
#-----------------------------------------------------------------


network:
  interface: "bond0" # Interface the Bedrock Filter will run on
  xdpmode: "AUTO" # AUTO, DRV, SKB (GENERIC), NIC
  

prometheus:  #Configuration for prometheus stats
  enabled: true
  bind: "0.0.0.0:9090"
  pop: "Gotham, City" # Point-of-presence label used in Prometheus metrics

protection:
  ratelimit: true # Enable rate limiting
  limit: 300 # Rate limit per ip in packets per second
  block: true # Will add IPs to the blocklist if they surpass the rate limit
  binds:  # Destinations that should go through the Bedrock Filter
    - "1.1.1.1:19132"
    - "2.2.2.2:19132"
    - "0.0.0.0:19132" # To filter EVERYTHING on a specific port use 0.0.0.0

#The blocklist feature will drop all further traffic from an IP after it has sent an invalid raknet packet
blocklist:
  enabled: true # Enable blocklist
  blocktime: 60 # How many seconds to wait before cleaning the blocklist
  global: true # Drop all traffic from blocked IPs regardless of Protocol or Destination
`

	// Check if the config file already exists
	if _, err := os.Stat(configPath); err == nil {
		log.Fatalf("\033[31m[BEDROCK-XDP] \033[0mConfiguration file already exists \033[31m(%s)\033[0m", configPath)
	}

	// Write the manually constructed YAML content to a file
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		log.Fatalf("\033[31m[BEDROCK-XDP] \033[0mError writing to file \033[31m(%s)\033[0m", err)
	}

}
