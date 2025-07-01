struct bpf_map_def SEC("maps") udp_drop_pps = { //UDP Dropped Packets/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") udp_drop_bps = { //UDP Dropped Bits/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") other_drop_pps = { //Other Dropped Packets/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") other_drop_bps = { //Other Dropped Bits/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

