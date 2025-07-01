package analytics

// StatIntervalSec defines how often the eBPF maps are reset and therefore the
// length of the window over which packet/bit counters accumulate. The console
// and Prometheus rates are converted to per-second by dividing raw totals by
// this value.
var StatIntervalSec = 5
