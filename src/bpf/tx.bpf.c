// SPDX-License-Identifier: GPL-2.0
/*
 * Sender side. Userspace feeds one template frame per stream to xpeed_tx
 * through BPF_PROG_RUN in live-frames mode; each run stamps the frame and
 * redirects it out of the egress interface.
 */
#include <linux/udp.h>
#include "common.h"

volatile const __u32 tx_ifindex;
volatile const __u32 tx_udp_off;
/* This process, as seen from its PID namespace (dev/ino of /proc/self/ns/pid). */
volatile const __u64 tx_pidns_dev;
volatile const __u64 tx_pidns_ino;
volatile const __u32 tx_tgid;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_STREAMS);
	__type(key, __u32);
	__type(value, struct tx_stream);
} tx_streams SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tx_xmit);
} tx_xmit SEC(".maps");

/*
 * Live frames are recycled with whatever the previous run wrote, so the old
 * words and checksum always match and an RFC 1624 update is enough.
 */
static __always_inline void put_be(__be16 *w, int n, __u64 val, __u32 *delta)
{
#pragma unroll
	for (int i = n - 1; i >= 0; i--, val >>= 16) {
		__be16 new = bpf_htons((__u16)val);

		*delta += (__u16)~w[i] + new;
		w[i] = new;
	}
}

SEC("xdp")
int xpeed_tx(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udp = data + (tx_udp_off & 0xff);
	struct xpeed_hdr *hdr = (void *)(udp + 1);
	struct tx_stream *st;
	__u32 stream, delta = 0;

	if ((void *)(hdr + 1) > data_end)
		return XDP_ABORTED;
	stream = bpf_ntohs(hdr->stream);
	st = bpf_map_lookup_elem(&tx_streams, &stream);
	if (!st)
		return XDP_ABORTED;

	put_be(hdr->seq, 3, st->packets++, &delta);
	put_be(hdr->ts, 4, bpf_ktime_get_ns(), &delta);
	/* Templates always carry a checksum, never the IPv4 "none" (0). */
	delta += (__u16)~udp->check;
	delta = (delta & 0xffff) + (delta >> 16);
	delta = (delta & 0xffff) + (delta >> 16);
	udp->check = (__u16)~delta ?: 0xffff;
	return bpf_redirect(tx_ifindex, 0);
}

/* Attached to the egress interface: many drivers only set up XDP TX queues
 * (needed to be a redirect target) while an XDP program is loaded. */
SEC("xdp")
int xpeed_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

struct net_device {
	int ifindex;
} __attribute__((preserve_access_index));

/*
 * The tracepoints fire for every XDP redirect on the host. Ours run from our
 * own BPF_PROG_RUN syscalls, so the current task tells them apart.
 */
static __always_inline struct tx_xmit *own_xmit(void)
{
	struct bpf_pidns_info ns;
	__u32 key = 0;

	if (bpf_get_ns_current_pid_tgid(tx_pidns_dev, tx_pidns_ino, &ns, sizeof(ns)) || ns.tgid != tx_tgid)
		return 0;
	return bpf_map_lookup_elem(&tx_xmit, &key);
}

/* Frames the egress driver accepted or dropped (e.g. TX ring full). */
SEC("tp_btf/xdp_devmap_xmit")
int xpeed_xmit(__u64 *ctx)
{
	const struct net_device *to = (void *)ctx[1];
	struct tx_xmit *x;

	if (to->ifindex != tx_ifindex || !(x = own_xmit()))
		return 0;
	x->sent += (int)ctx[2];
	x->drops += (int)ctx[3];
	return 0;
}

/* Redirects that failed before the driver: device down, frame over the MTU,
 * no XDP TX support. */
SEC("tp_btf/xdp_redirect_err")
int xpeed_redirect_err(__u64 *ctx)
{
	struct tx_xmit *x = own_xmit();

	if (x)
		x->drops++;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
