struct bpf_map_def SEC("maps") protected_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64), // upper 32 bits: IPv4 addr, lower 16 bits: port
    .value_size = sizeof(__u8),
    .max_entries = 256,
};

// IPv4 Blocklist map: key = src IP (u32 network byte order), value = 1 (present)
struct bpf_map_def SEC("maps") blocklist_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 131070,
};

// Single-element array acting as global enable flag for blocklist (0=off,1=on)
struct bpf_map_def SEC("maps") blocklist_global = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 1,
};

// Per-source-IP packet counter refreshed each second by user space
struct bpf_map_def SEC("maps") ratelimit_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32), // src IPv4
    .value_size = sizeof(__u32),
    .max_entries = 131070,
};

// Array[0] holds per-second limit (0 disables rate-limit)
struct bpf_map_def SEC("maps") ratelimit_limit = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// Array[0] flag => 1: exceeding limit blocks IP via blocklist; 0: just drop
struct bpf_map_def SEC("maps") ratelimit_block = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 1,
};

// 64-bit counter of total IP block events; userspace reads and resets.
struct bpf_map_def SEC("maps") block_counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
}; 