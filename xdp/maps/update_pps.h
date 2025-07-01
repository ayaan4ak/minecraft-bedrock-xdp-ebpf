#ifndef _UPDATEPPS_H
#define _UPDATEPPS_H

#include <linux/bpf.h>
#include <linux/ip.h>

// Function to update packet and byte counts in the maps
static inline void update_pps_counts(struct bpf_map_def *total_pps_map) {

    // Update total packet count
    __u32 total_key = 0;
    __u64 *total_count = bpf_map_lookup_elem(total_pps_map, &total_key);
    if (total_count) {
        *total_count += 1;
    } else {
        __u64 initial_total = 1;
        bpf_map_update_elem(total_pps_map, &total_key, &initial_total, BPF_ANY);
    }

}

#endif // _UPDATE_H