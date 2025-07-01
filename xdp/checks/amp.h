struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u8),
    .max_entries = 128,
};

static __always_inline int ampcheck(__u16 src_port) {
    __u8 *value;
    __u16 port = src_port;
    // Check if the src_port is in the port_map
    value = bpf_map_lookup_elem(&port_map, &port);
    if (value) {
        return 1; // Port found in map
    }

    return 0; // Port not found
}