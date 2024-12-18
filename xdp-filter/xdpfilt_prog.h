/* SPDX-License-Identifier: GPL-2.0 */

/* XDP filter program fragment. This header file contains the full-featured
 * program, split up with ifdefs. The actual program files xdpfilt_*.c
 * include this file with different #defines to create the
 * different eBPF program sections that include only the needed features.
 */

#ifndef __XDPFILT_PROG_H
#define __XDPFILT_PROG_H

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>
#include <bpf/bpf_endian.h>
// #include "vmlinux.h"

#include "common_kern_user.h"

/* Defines xdp_stats_map */
#include "xdp/xdp_stats_kern.h"
#include "xdp/parsing_helpers.h"

#ifdef FILT_MODE_DENY
#define VERDICT_HIT XDP_PASS
#define VERDICT_MISS XDP_DROP
#define FEATURE_OPMODE FEAT_DENY
#else
#define VERDICT_HIT XDP_DROP
#define VERDICT_MISS XDP_PASS
#define FEATURE_OPMODE FEAT_ALLOW
#endif

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

struct nf_conn {
	unsigned long status;
};

struct bpf_ct_opts___local {
	int netns_id;
	int error;
	__u8 l4proto;
	__u8 dir;
	__u8 reserved[2];
} __attribute__((preserve_access_index));

#define BPF_F_CURRENT_NETNS (-1)
#define IPS_CONFIRMED_BIT  3
#define	IPS_CONFIRMED      (1 << IPS_CONFIRMED_BIT)

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx, struct bpf_sock_tuple *bpf_tuple,
		  u32 tuple__sz, struct bpf_ct_opts___local *opts, u32 opts__sz) __ksym;

extern void bpf_ct_release(struct nf_conn *ct) __ksym;

struct ct_key {
	struct xdp_md *ctx;
	struct bpf_sock_tuple tuple;
	__u8 l4proto;
};

#define CHECK_RET(ret)                        \
	do {                                  \
		if ((ret) < 0) {              \
			action = XDP_ABORTED; \
			goto out;             \
		}                             \
	} while (0)

#define CHECK_VERDICT(type, param)                                           \
	do {                                                                 \
		if ((action = lookup_verdict_##type(param)) != VERDICT_MISS) \
			goto out;                                            \
	} while (0)

#define CHECK_MAP(map, key, mask)                               \
	do {                                                    \
		__u64 *value;                                   \
		value = bpf_map_lookup_elem(map, key);          \
		if ((value) && (*(value) & (mask)) == (mask)) { \
			*value += (1 << COUNTER_SHIFT);         \
			return VERDICT_HIT;                     \
		}                                               \
	} while (0)

#if defined(FILT_MODE_TCP) || defined(FILT_MODE_UDP)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_PORTS SEC(".maps");

#ifdef FILT_MODE_TCP
static int __always_inline lookup_verdict_tcp(struct tcphdr *tcphdr)
{
	__u32 key;

	key = tcphdr->dest;
	CHECK_MAP(&filter_ports, &key, MAP_FLAG_DST | MAP_FLAG_TCP);
	key = tcphdr->source;
	CHECK_MAP(&filter_ports, &key, MAP_FLAG_SRC | MAP_FLAG_TCP);
	return VERDICT_MISS;
}
#define FEATURE_TCP FEAT_TCP
#else
#define FEATURE_TCP 0
#endif

#ifdef FILT_MODE_UDP
static int __always_inline lookup_verdict_udp(struct udphdr *udphdr)
{
	__u32 key;

	key = udphdr->dest;
	CHECK_MAP(&filter_ports, &key, MAP_FLAG_DST | MAP_FLAG_UDP);
	key = udphdr->source;
	CHECK_MAP(&filter_ports, &key, MAP_FLAG_SRC | MAP_FLAG_UDP);
	return VERDICT_MISS;
}
#define FEATURE_UDP FEAT_UDP
#else
#define FEATURE_UDP 0
#endif

#else
#define FEATURE_UDP 0
#define FEATURE_TCP 0
#endif /* TCP || UDP */

#ifdef FILT_MODE_CT

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_CT SEC(".maps");

static int __always_inline lookup_verdict_ct(struct ct_key conntrack)
{
	__u32 port;
	__u64 mask = MAP_FLAG_TCP; // test with tcp conntrack
	struct bpf_ct_opts___local opts_def = { .reserved[0] = 0, .l4proto = conntrack.l4proto ,.netns_id = BPF_F_CURRENT_NETNS}; 
	struct nf_conn *ct;

	ct = bpf_xdp_ct_lookup(conntrack.ctx, &conntrack.tuple, sizeof(conntrack.tuple.ipv4), &opts_def, sizeof(opts_def));
	// Allow all + deny rules by port number
	if (ct) {
		unsigned long status = ct->status;
		bpf_ct_release(ct);
		if (status & IPS_CONFIRMED)
			// mask |= MAP_STATE_CT_ESTABLISHED;
			return VERDICT_MISS;
	} else if (opts_def.error != -ENOENT) {
		// Failed to lookup conntrack
		return XDP_ABORTED;
	} else {
		/* error == -ENOENT || !(status & IPS_CONFIRMED) */
		mask |= MAP_STATE_CT_NEW;

		port = conntrack.tuple.ipv4.dport;  
		CHECK_MAP(&filter_ct, &port, mask | MAP_FLAG_DST);
		port = conntrack.tuple.ipv4.sport;  
		CHECK_MAP(&filter_ct, &port, mask | MAP_FLAG_SRC);	
	}
	return VERDICT_MISS;
}

#define CHECK_VERDICT_CT(param) CHECK_VERDICT(ct, param)
#define FEATURE_CT FEAT_CT
#else
#define FEATURE_CT 0
#define CHECK_VERDICT_CT(param)
#endif

#ifdef FILT_MODE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_IPV4 SEC(".maps");

static int __always_inline lookup_verdict_ipv4(struct iphdr *iphdr)
{
	__u32 addr;
	addr = iphdr->daddr;
	CHECK_MAP(&filter_ipv4, &addr, MAP_FLAG_DST);
	addr = iphdr->saddr;
	CHECK_MAP(&filter_ipv4, &addr, MAP_FLAG_SRC);
	return VERDICT_MISS;
}

#define CHECK_VERDICT_IPV4(param) CHECK_VERDICT(ipv4, param)
#define FEATURE_IPV4 FEAT_IPV4
#else
#define FEATURE_IPV4 0
#define CHECK_VERDICT_IPV4(param)
#endif /* FILT_MODE_IPV4 */

#ifdef FILT_MODE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct in6_addr);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_IPV6 SEC(".maps");

static int __always_inline lookup_verdict_ipv6(struct ipv6hdr *ipv6hdr)
{
	struct in6_addr addr;

	addr = ipv6hdr->daddr;
	CHECK_MAP(&filter_ipv6, &addr, MAP_FLAG_DST);
	addr = ipv6hdr->saddr;
	CHECK_MAP(&filter_ipv6, &addr, MAP_FLAG_SRC);
	return VERDICT_MISS;
}

#define CHECK_VERDICT_IPV6(param) CHECK_VERDICT(ipv6, param)
#define FEATURE_IPV6 FEAT_IPV6
#else
#define FEATURE_IPV6 0
#define CHECK_VERDICT_IPV6(param)
#endif /* FILT_MODE_IPV6 */

#ifdef FILT_MODE_ETHERNET
struct ethaddr {
	__u8 addr[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct ethaddr);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_ETHERNET SEC(".maps");

static int __always_inline lookup_verdict_ethernet(struct ethhdr *eth)
{
	struct ethaddr addr = {};

	__builtin_memcpy(&addr, eth->h_dest, sizeof(addr));
	CHECK_MAP(&filter_ethernet, &addr, MAP_FLAG_DST);
	__builtin_memcpy(&addr, eth->h_source, sizeof(addr));
	CHECK_MAP(&filter_ethernet, &addr, MAP_FLAG_SRC);
	return VERDICT_MISS;
}

#define CHECK_VERDICT_ETHERNET(param) CHECK_VERDICT(ethernet, param)
#define FEATURE_ETHERNET FEAT_ETHERNET
#else
#define FEATURE_ETHERNET 0
#define CHECK_VERDICT_ETHERNET(param)
#endif /* FILT_MODE_ETHERNET */

#ifndef FUNCNAME
#define FUNCNAME xdp_filt_unknown
#endif

struct {
	__uint(priority, 10);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(FUNCNAME);

SEC("xdp")
int FUNCNAME(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 action = VERDICT_MISS; /* Default action */
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;

	nh.pos = data;
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	CHECK_RET(eth_type);
	CHECK_VERDICT_ETHERNET(eth);

#if defined(FILT_MODE_IPV4) || defined(FILT_MODE_IPV6) || \
	defined(FILT_MODE_TCP) || defined(FILT_MODE_UDP) || defined(FILT_MODE_CT)
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	int ip_type;
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		CHECK_RET(ip_type);
		CHECK_VERDICT_IPV4(iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		CHECK_RET(ip_type);

		CHECK_VERDICT_IPV6(ipv6hdr);
	} else {
		goto out;
	}

#ifdef FILT_MODE_UDP
	struct udphdr *udphdr;
	if (ip_type == IPPROTO_UDP) {
		CHECK_RET(parse_udphdr(&nh, data_end, &udphdr));
		CHECK_VERDICT(udp, udphdr);

#ifdef FILT_MODE_CT
		struct ct_key conntrack = {
			.ctx = ctx,
			.tuple.ipv4.daddr = iphdr->daddr,
			.tuple.ipv4.saddr = iphdr->saddr,
			.tuple.ipv4.dport = udphdr->dest,
			.tuple.ipv4.sport = udphdr->source,
			.l4proto = ip_type
		};
		CHECK_VERDICT_CT(conntrack);
#endif
	}
#endif /* FILT_MODE_UDP */

#ifdef FILT_MODE_TCP
	struct tcphdr *tcphdr;
	if (ip_type == IPPROTO_TCP) {
		CHECK_RET(parse_tcphdr(&nh, data_end, &tcphdr));
#ifdef FILT_MODE_CT
		struct ct_key conntrack = {
			.ctx = ctx,
			.tuple.ipv4.daddr = iphdr->daddr,
			.tuple.ipv4.saddr = iphdr->saddr,
			.tuple.ipv4.dport = tcphdr->dest,
			.tuple.ipv4.sport = tcphdr->source,
			.l4proto = ip_type
		};
		CHECK_VERDICT_CT(conntrack);
#endif
		CHECK_VERDICT(tcp, tcphdr);

		}
#endif /* FILT_MODE_TCP*/
#endif /* FILT_MODE_{IPV4,IPV6,TCP,UDP} */
out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
__u32 _features SEC("features") = (FEATURE_ETHERNET | FEATURE_IPV4 |
				   FEATURE_IPV6 | FEATURE_UDP | FEATURE_TCP | FEATURE_CT|
				   FEATURE_OPMODE);

#else
#error "Multiple includes of xdpfilt_prog.h"
#endif // include guard
