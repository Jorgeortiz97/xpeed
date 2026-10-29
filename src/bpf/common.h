/* SPDX-License-Identifier: GPL-2.0 */
/* Definitions shared by the BPF programs; mirrored in src/bpf.rs. */
#ifndef XPEED_COMMON_H
#define XPEED_COMMON_H

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#else
#define bpf_htons(x) (x)
#endif
#define bpf_ntohs(x) bpf_htons(x)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino, struct bpf_pidns_info *nsdata, __u32 size) =
	(void *)BPF_FUNC_get_ns_current_pid_tgid;

#define MAX_STREAMS 256
#define MAX_VLANS 2

/*
 * UDP payload of every test packet. 18 bytes, so a minimal IPv4 frame is 60
 * bytes (64 on the wire). Kept as 16-bit words so it needs no packing and
 * the sender can update the UDP checksum word by word.
 */
struct xpeed_hdr {
	__be16 magic;	/* per-test cookie handed out by the server */
	__be16 stream;
	__be16 seq[3];	/* 48-bit sequence number */
	__be16 ts[4];	/* sender bpf_ktime_get_ns() */
};

/* Padded to a cache line: each entry is written by a different CPU. */
struct tx_stream {
	__u64 packets;
	__u64 pad[7];
};

struct tx_xmit {
	__u64 sent;
	__u64 drops;
};

struct rx_stream {
	__u64 packets;
	__u64 next_seq;
	__u64 out_of_order;
	__u64 jitter;	/* RFC 3550 interarrival jitter in ns, scaled by 16 */
	__s64 last_transit;
};

#endif
