struct bpf_map_def SEC("maps") udp_pass_pps = { //UDP Passed Packets/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") udp_pass_bps = { //UDP Passed Bits/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};


struct bpf_map_def SEC("maps") other_pass_pps = { //Other Passed Packets/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") other_pass_bps = { //Other Passed Bits/s
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};