#ifndef _UPDATEBPS_H
#define _UPDATEBPS_H

#include <linux/bpf.h>
#include <linux/ip.h>

// Function to update packet and byte counts in the maps
static inline void update_bps_counts(struct bpf_map_def *total_bps_map, __u64 pkt_size_bits) { 

    // Update total BPS count
    __u32 total_key = 0;
    __u64 *total_bits_count = bpf_map_lookup_elem(total_bps_map, &total_key);
    if (total_bits_count) {
        *total_bits_count += pkt_size_bits;
    } else {
        bpf_map_update_elem(total_bps_map, &total_key, &pkt_size_bits, BPF_ANY);
    }
}

#endif // _UPDATE_H