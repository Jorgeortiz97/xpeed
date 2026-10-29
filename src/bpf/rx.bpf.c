// SPDX-License-Identifier: GPL-2.0
/* Receiver side: counts xpeed test packets per stream and drops them. */
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include "common.h"

/* Unlike the uapi ethhdr, not packed, so the ethertype is one 16-bit load. */
struct eth_hdr {
	__u8 dst[6];
	__u8 src[6];
	__be16 proto;
};

struct vlan_hdr {
	__be16 tci;
	__be16 proto;
};

volatile const __be16 rx_port;

/* Per-test cookie; 0 while no test is running. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __be16);
} rx_cookie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_STREAMS);
	__type(key, __u32);
	__type(value, struct rx_stream);
} rx_streams SEC(".maps");

static __always_inline __u64 get_be(const __be16 *w, int n)
{
	__u64 val = 0;

#pragma unroll
	for (int i = 0; i < n; i++)
		val = val << 16 | bpf_ntohs(w[i]);
	return val;
}

SEC("xdp")
int xpeed_rx(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth = data;
	struct xpeed_hdr *hdr;
	struct rx_stream *s;
	struct udphdr *udp;
	__be16 *cookie;
	__u32 key = 0;
	__be16 proto;
	__s64 transit;
	__u64 seq;
	void *l3;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	proto = eth->proto;
	l3 = eth + 1;
#pragma unroll
	for (int i = 0; i < MAX_VLANS; i++) {
		struct vlan_hdr *vlan = l3;

		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		if ((void *)(vlan + 1) > data_end)
			return XDP_PASS;
		proto = vlan->proto;
		l3 = vlan + 1;
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = l3;

		/* 0x3fff: more-fragments flag and fragment offset */
		if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP ||
		    ip->frag_off & bpf_htons(0x3fff))
			return XDP_PASS;
		udp = l3 + ip->ihl * 4;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;

		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		udp = (void *)(ip6 + 1);
	} else {
		return XDP_PASS;
	}

	hdr = (void *)(udp + 1);
	if ((void *)(hdr + 1) > data_end || udp->dest != rx_port)
		return XDP_PASS;
	cookie = bpf_map_lookup_elem(&rx_cookie, &key);
	if (!cookie || !*cookie || hdr->magic != *cookie)
		return XDP_PASS;
	key = bpf_ntohs(hdr->stream);
	s = bpf_map_lookup_elem(&rx_streams, &key);
	if (!s)
		return XDP_DROP;

	/* Clocks differ between hosts, but jitter only needs transit deltas. */
	seq = get_be(hdr->seq, 3);
	transit = bpf_ktime_get_ns() - get_be(hdr->ts, 4);
	if (s->packets) {
		__s64 d = transit - s->last_transit;

		s->jitter += (d < 0 ? -d : d) - ((s->jitter + 8) >> 4);
	}
	s->last_transit = transit;
	if (seq < s->next_seq)
		s->out_of_order++;
	else
		s->next_seq = seq + 1;
	s->packets++;
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
