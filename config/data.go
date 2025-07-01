package config

// Config mirrors the simplified YAML schema produced in config/init.go
// and consumed by main/main.go & analytics.
type Config struct {
	Network struct {
		Interface string `yaml:"interface"`
		XdpMode   string `yaml:"xdpmode"`
	} `yaml:"network"`

	Prometheus struct {
		Enabled bool   `yaml:"enabled"`
		Bind    string `yaml:"bind"`
		Pop     string `yaml:"pop"`
	} `yaml:"prometheus"`

	Protection struct {
		Ratelimit bool     `yaml:"ratelimit"`
		Block     bool     `yaml:"block"`
		Limit     int      `yaml:"limit"`
		Binds     []string `yaml:"binds"`
	} `yaml:"protection"`

	Blocklist struct {
		Enabled   bool `yaml:"enabled"`
		Blocktime int  `yaml:"blocktime"`
		Global    bool `yaml:"global"`
	} `yaml:"blocklist"`
}
