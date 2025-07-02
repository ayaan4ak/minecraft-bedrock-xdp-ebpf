#include <stdbool.h>   /* we use bool in RakNet check */
#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h> // For ethhdr and ETH_P_* values
#include <linux/in.h>       // For IPPROTO_TCP and IPPROTO_UDP
#include <linux/udp.h>      // For udphdr
#include "maps/pass.h"     // Consolidated PASS maps
#include "maps/drop.h"     // Consolidated DROP maps
#include "maps/update_pps.h"
#include "maps/update_bps.h"
#include "maps/mitigation.h"
#include "checks/amp.h" // AMP reflection port detection
#include "checks/blocklist.h"

//#define bpf_htons(x) ((__be16)___constant_swab16((x)))



SEC("xdp/main")
int xdp_main_prog(struct xdp_md* ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 pkt_size_bits = (__u64)(data_end - data) * 8;


    // Check if the packet is large enough for an Ethernet header
    if ((void *)(eth + 1) > data_end)
    {
        update_pps_counts(&other_pass_pps);
        update_bps_counts(&other_pass_bps, pkt_size_bits);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        update_pps_counts(&other_drop_pps);
        update_bps_counts(&other_drop_bps, pkt_size_bits);
        return XDP_DROP;
    }

    // Skip non-IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        update_pps_counts(&other_pass_pps);
        update_bps_counts(&other_pass_bps, pkt_size_bits);
        return XDP_PASS;
    }





    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
    {
        update_pps_counts(&other_pass_pps);
        update_bps_counts(&other_pass_bps, pkt_size_bits);
        return XDP_PASS;
    }

    __u32 src_ip_bl = ip->saddr;
    if (blocklist_should_drop(src_ip_bl, false)) {
        update_pps_counts(&other_drop_pps);
        update_bps_counts(&other_drop_bps, pkt_size_bits);
        return XDP_DROP;
    }

    switch (ip->protocol) {
        case IPPROTO_UDP:
        {


            // Start Checks for UDP
            struct udphdr *udp = (void *)ip + sizeof(struct iphdr);
            if ((void *)(udp + 1) > data_end) {
                // Incomplete UDP header
                update_pps_counts(&udp_drop_pps);
                update_bps_counts(&udp_drop_bps, pkt_size_bits);
                return XDP_DROP;
            }

            /* Verify destination matches a protected bind */
            __u64 key;
            __u32 dst_ip_host = bpf_ntohl(ip->daddr); // host-order for consistency with userspace
            __u16 dst_port_host = bpf_ntohs(udp->dest);
            key = ((__u64)dst_ip_host << 16) | (__u64)dst_port_host;

            __u8 *prot_val = bpf_map_lookup_elem(&protected_map, &key);
            if (!prot_val) {
                /* Check wildcard IP (0.0.0.0) for this port */
                __u64 any_key = (__u64)dst_port_host; // upper 48 bits zero
                prot_val = bpf_map_lookup_elem(&protected_map, &any_key);
            }

            if (!prot_val) {
                // Count as OTHER pass (not protected traffic)
                //Or should i count as udp?
                update_pps_counts(&other_pass_pps);
                update_bps_counts(&other_pass_bps, pkt_size_bits);
                return XDP_PASS;
            }

            /* Drop packets whose source port matches known amp srcports */
            if (ampcheck(bpf_ntohs(udp->source))) {
                update_pps_counts(&udp_drop_pps);
                update_bps_counts(&udp_drop_bps, pkt_size_bits);
                return XDP_DROP;
            }

            if (blocklist_should_drop(src_ip_bl, true)) {
                update_pps_counts(&udp_drop_pps);
                update_bps_counts(&udp_drop_bps, pkt_size_bits);
                return XDP_DROP;
            }

            
            /* RakNet validation */
            // Ensure minimal payload size (3 bytes)
            __u8 *payload_start = (__u8 *)(udp + 1);
            if ((void *)payload_start < data_end) {
                if ((void *)(payload_start + 3) > data_end) {
                    update_pps_counts(&udp_drop_pps);
                    update_bps_counts(&udp_drop_bps, pkt_size_bits);
                    __u32 src = ip->saddr;
                    block_ip_if_new(src);
                    return XDP_DROP;
                }

                // Valid Raknet packet IDs list
                __u8 pid = *payload_start;
                bool pid_ok = false;
                switch (pid) {
                    case 0x00: case 0x01: case 0x02: case 0x05: case 0x07: case 0x09: case 0x13:
                    case 0xc0:
                        pid_ok = true; break;
                    default:
                        //Custom game packets
                        if (pid >= 0x80 && pid <= 0xFE) pid_ok = true;
                }
                if (!pid_ok) {
                    update_pps_counts(&udp_drop_pps);
                    update_bps_counts(&udp_drop_bps, pkt_size_bits);
                    __u32 src = ip->saddr;
                    block_ip_if_new(src);
                    return XDP_DROP;
                }

                // Check magic if required (Some packets dont send it for whatever fuckass reason bruv)
                bool magic_needed = true;
                switch (pid) { case 0xc0: case 0x84: case 0x8c: case 0x09: case 0x88: case 0x80: case 0xa0: case 0x13: magic_needed = false; }
                if (magic_needed) {
                    if ((void *)(payload_start + 17) > data_end) {
                        update_pps_counts(&udp_drop_pps); update_bps_counts(&udp_drop_bps, pkt_size_bits); 
                        __u32 src = ip->saddr;
                        block_ip_if_new(src);
                        return XDP_DROP;
                    }
                    const unsigned char rak_magic[16] = {0x00,0xff,0xff,0x00,0xfe,0xfe,0xfe,0xfe,
                                                        0xfd,0xfd,0xfd,0xfd,0x12,0x34,0x56,0x78};
#pragma unroll
                    for (int mi = 0; mi < 16; mi++) {
                        if (*((unsigned char *)(payload_start + 1 + mi)) != rak_magic[mi]) {
                            update_pps_counts(&udp_drop_pps);
                            update_bps_counts(&udp_drop_bps, pkt_size_bits);
                            __u32 src = ip->saddr;
                            block_ip_if_new(src);
                            return XDP_DROP;
                        }
                    }
                }

                                

                /* Rate-limit check per source IP */
                __u32 rl_key = 0;
                __u32 *limit_ptr = bpf_map_lookup_elem(&ratelimit_limit, &rl_key);
                if (limit_ptr && *limit_ptr) {
                    __u32 src_ip = ip->saddr; // network order key
                    __u32 *hit_counter = bpf_map_lookup_elem(&ratelimit_map, &src_ip);
                    if (hit_counter) {
                        __u32 count = *hit_counter;
                        if (count >= *limit_ptr) {
                            /* decide block or drop */
                            __u8 *bl_mode = bpf_map_lookup_elem(&ratelimit_block, &rl_key);
                            if (bl_mode && *bl_mode) {
                                block_ip_if_new(src_ip);
                            }
                            update_pps_counts(&udp_drop_pps);
                            update_bps_counts(&udp_drop_bps, pkt_size_bits);
                            return XDP_DROP;
                        }
                        count++;
                        bpf_map_update_elem(&ratelimit_map, &src_ip, &count, BPF_EXIST);
                    } else {
                        __u32 new_cnt = 1;
                        bpf_map_update_elem(&ratelimit_map, &src_ip, &new_cnt, BPF_NOEXIST);
                    }
                }

            } else {
                update_pps_counts(&udp_drop_pps);
                update_bps_counts(&udp_drop_bps, pkt_size_bits);
                __u32 src = ip->saddr;
                block_ip_if_new(src);
                return XDP_DROP;
            }

            update_pps_counts(&udp_pass_pps);
            update_bps_counts(&udp_pass_bps, pkt_size_bits);
            return XDP_PASS;

        }
        case IPPROTO_TCP:
        {

            //Implement TCP Checks if you want
            update_pps_counts(&other_pass_pps);
            update_bps_counts(&other_pass_bps, pkt_size_bits);
            return XDP_PASS;
        }
    }

    update_pps_counts(&other_pass_pps);
    update_bps_counts(&other_pass_bps, pkt_size_bits);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";