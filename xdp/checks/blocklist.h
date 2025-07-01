// Helper: add src IP to blocklist and increment counter only if not already present
static __always_inline void block_ip_if_new(__u32 src_ip) {
    __u8 val = 1;
    // Insert only if key does not exist; returns 0 on success
    if (bpf_map_update_elem(&blocklist_map, &src_ip, &val, BPF_NOEXIST) == 0) {
        __u32 key = 0;
        __u64 zero = 0, new_val;
        __u64 *cur = bpf_map_lookup_elem(&block_counter, &key);
        if (cur) {
            new_val = *cur + 1;
        } else {
            new_val = 1;
        }
        bpf_map_update_elem(&block_counter, &key, &new_val, BPF_ANY);
    }
}

// Query if global blocklist mode is enabled (blocklist_global map key 0 == 1)
static __always_inline bool blocklist_global_enabled() {
    __u32 key = 0;
    __u8 *g = bpf_map_lookup_elem(&blocklist_global, &key);
    return g && *g;
}

// Check if a source IP is present in blocklist_map
static __always_inline bool ip_is_blocked(__u32 src_ip) {
    return bpf_map_lookup_elem(&blocklist_map, &src_ip) != NULL;
}

/*
 * Decide if a packet from src_ip should be dropped given current config.
 * If the global mode is enabled we always drop a blocked IP.
 * Otherwise we only drop when the traffic is headed to a protected bind
 * (is_protected == true).
 */
static __always_inline bool blocklist_should_drop(__u32 src_ip, bool is_protected) {
    if (blocklist_global_enabled()) {
        return ip_is_blocked(src_ip);
    }
    if (is_protected) {
        return ip_is_blocked(src_ip);
    }
    return false;
}