//go:build ignore

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

#include "common.h"
#include "bpf_endian.h"

#include "packet_parse.h"

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1
#endif

// DNS response codes
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_TIMEOUT -1 // Special value to indicate drop

enum config_flags {
	CONFIG_INJECT_NXDOMAIN = 0x01,
	CONFIG_INJECT_SERVFAIL = 0x02,
	CONFIG_INJECT_TIMEOUT  = 0x04,
};

struct config_value {
	enum config_flags flags;
	__u16 port_lower;
	__u16 port_upper;
};

// DNS header structure
struct dns_header {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

// IPv4 LPM Trie key
struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 addr;
} __attribute__((packed));

// IPv6 LPM Trie key
struct ipv6_lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
} __attribute__((packed));

struct metrics_value {
	__u64 seen;
	__u64 ipv4;
	__u64 ipv6;
	__u64 dns_matched;
	__u64 injected;
	__u64 injected_nxdomain;
	__u64 injected_servfail;
	__u64 injected_timeout;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config_value);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u8);
} ipv4_cidr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv6_lpm_key);
	__type(value, __u8);
} ipv6_cidr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct metrics_value);
} metrics_map SEC(".maps");


static __always_inline struct config_value *get_config()
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline int ipv4_matches(__u32 saddr, __u32 daddr)
{
	struct ipv4_lpm_key key = { .prefixlen = 32 };

	key.addr = saddr;
	if (bpf_map_lookup_elem(&ipv4_cidr_map, &key)) {
		return 1;
	}

	key.addr = daddr;
	if (bpf_map_lookup_elem(&ipv4_cidr_map, &key)) {
		return 1;
	}

	return 0;
}

static __always_inline int ipv6_matches(struct in6_addr *saddr, struct in6_addr *daddr)
{
	struct ipv6_lpm_key key = { .prefixlen = 128 };

	__builtin_memcpy(key.addr, saddr, 16);
	if (bpf_map_lookup_elem(&ipv6_cidr_map, &key)) {
		return 1;
	}

	__builtin_memcpy(key.addr, daddr, 16);
	if (bpf_map_lookup_elem(&ipv6_cidr_map, &key)) {
		return 1;
	}

	return 0;
}

static __always_inline int port_in_range(__u16 lower, __u16 upper, __u16 sport, __u16 dport)
{
	return (sport >= lower && sport <= upper) ||
	       (dport >= lower && dport <= upper);
}

static __always_inline int is_dns_query(struct hdr_cursor *hc)
{
	struct dns_header *dns = hc->pos;

	if (hc->pos + sizeof(struct dns_header) > hc->data_end) {
		return 0;
	}

	// Check if this is a DNS query (QR bit = 0)
	__u16 flags = bpf_ntohs(dns->flags);
	return (flags & 0x8000) == 0; // QR bit is 0 for queries
}

static __always_inline int inject_dns_error(struct __sk_buff *skb, __u32 eth_offset, __u32 ip_offset, __u32 udp_offset,
											__u32 dns_offset, int error_type, int is_ipv6)
{
	struct dns_header dns_hdr;

	if (bpf_skb_load_bytes(skb, dns_offset, &dns_hdr, sizeof(dns_hdr)) < 0) {
		return 0;
	}

	__u16 flags = bpf_ntohs(dns_hdr.flags);
	flags |= 0x8000; // QR (response)
	flags |= 0x0080; // RA (recursion available)
	flags = (flags & 0xFFF0) | (__u16)error_type;

	dns_hdr.flags = bpf_htons(flags);
	dns_hdr.ancount = 0;
	dns_hdr.nscount = 0;
	dns_hdr.arcount = 0;

	if (bpf_skb_pull_data(skb, dns_offset + sizeof(dns_hdr)) < 0) {
		return 0;
	}

	if (bpf_skb_store_bytes(skb, dns_offset, &dns_hdr, sizeof(dns_hdr), BPF_F_RECOMPUTE_CSUM) < 0) {
		return 0;
	}

	// Swap IP addresses
	if (!is_ipv6) {
		struct iphdr iph;
		if (bpf_skb_load_bytes(skb, ip_offset, &iph, sizeof(iph)) < 0) {
			return 0;
		}
		__u32 tmp_addr = iph.saddr;
		iph.saddr = iph.daddr;
		iph.daddr = tmp_addr;
		if (bpf_skb_store_bytes(skb, ip_offset, &iph, sizeof(iph), BPF_F_RECOMPUTE_CSUM) < 0) {
			return 0;
		}
	} else {
		struct ipv6hdr ip6h;
		if (bpf_skb_load_bytes(skb, ip_offset, &ip6h, sizeof(ip6h)) < 0) {
			return 0;
		}
		struct in6_addr tmp_addr = ip6h.saddr;
		ip6h.saddr = ip6h.daddr;
		ip6h.daddr = tmp_addr;
		if (bpf_skb_store_bytes(skb, ip_offset, &ip6h, sizeof(ip6h), BPF_F_RECOMPUTE_CSUM) < 0) {
			return 0;
		}
	}

	struct udphdr udph;
	if (bpf_skb_load_bytes(skb, udp_offset, &udph, sizeof(udph)) < 0) {
		return 0;
	}
	__u16 tmp_port = udph.source;
	udph.source = udph.dest;
	udph.dest = tmp_port;
	if (bpf_skb_store_bytes(skb, udp_offset, &udph, sizeof(udph), BPF_F_RECOMPUTE_CSUM) < 0) {
		return 0;
	}

	if (eth_offset < ip_offset) {
		struct ethhdr eth;
		if (bpf_skb_load_bytes(skb, eth_offset, &eth, sizeof(eth)) < 0) {
			return 1;
		}
		unsigned char tmp_mac[6];
		__builtin_memcpy(tmp_mac, eth.h_source, 6);
		__builtin_memcpy(eth.h_source, eth.h_dest, 6);
		__builtin_memcpy(eth.h_dest, tmp_mac, 6);
		bpf_skb_store_bytes(skb, eth_offset, &eth, sizeof(eth), 0);
	}

	return 1;
}

static __always_inline int get_error_type(int flags)
{
	int has_nxdomain = (flags & CONFIG_INJECT_NXDOMAIN) != 0;
	int has_servfail = (flags & CONFIG_INJECT_SERVFAIL) != 0;
	int has_timeout  = (flags & CONFIG_INJECT_TIMEOUT) != 0;
	int count = has_nxdomain + has_servfail + has_timeout;

	if (count == 0) {
		return DNS_RCODE_NOERROR;
	}

	__u32 pick = 0;
	if (count > 1) {
		pick = bpf_get_prandom_u32() % count;
	}

	// Map pick index to the N-th enabled type
	if (has_nxdomain) {
		if (pick == 0) return DNS_RCODE_NXDOMAIN;
		pick--;
	}
	if (has_servfail) {
		if (pick == 0) return DNS_RCODE_SERVFAIL;
		pick--;
	}
	if (has_timeout) {
		if (pick == 0) return DNS_RCODE_TIMEOUT;
	}

	return DNS_RCODE_NXDOMAIN;
}

// Inject DNS error or drop packet for timeout
static __always_inline int inject_or_drop(struct __sk_buff *skb, __u32 eth_offset, __u32 ip_offset, __u32 udp_offset,
										  int error_type, int is_ipv6, struct metrics_value *mv)
{
	__u32 dns_offset = udp_offset + sizeof(struct udphdr);

	// For timeout, just drop the packet
	if (error_type == DNS_RCODE_TIMEOUT) {
		if (mv) {
			__sync_fetch_and_add(&mv->injected, 1);
			__sync_fetch_and_add(&mv->injected_timeout, 1);
		}
		return TC_ACT_SHOT; // Drop the packet
	}

	// Inject DNS error response
	if (!inject_dns_error(skb, eth_offset, ip_offset, udp_offset, dns_offset, error_type, is_ipv6)) {
		return TC_ACT_OK;
	}

	// Update metrics
	if (mv) {
		__sync_fetch_and_add(&mv->injected, 1);
		if (error_type == DNS_RCODE_NXDOMAIN) {
			__sync_fetch_and_add(&mv->injected_nxdomain, 1);
		} else if (error_type == DNS_RCODE_SERVFAIL) {
			__sync_fetch_and_add(&mv->injected_servfail, 1);
		}
	}

	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

static __always_inline int process_ipv4(struct __sk_buff *skb, struct hdr_cursor *hc, __u32 eth_offset, __u32 ip_offset,
										struct config_value *cfg, struct metrics_value *mv)
{
	struct iphdr *iph;
	struct udphdr *udph;
	int ip_proto;
	__u32 udp_offset;

	if (mv) {
		__sync_fetch_and_add(&mv->ipv4, 1);
	}

	ip_proto = parse_iphdr(hc, &iph);
	if (ip_proto < 0 || ip_proto != IPPROTO_UDP) {
		return TC_ACT_OK;
	}

	udp_offset = ip_offset + ((__u32)iph->ihl * 4);

	hc->pos = (void *)(long)skb->data + udp_offset;
	if (hc->pos > hc->data_end) {
		return TC_ACT_OK;
	}

	if (parse_udphdr(hc, &udph) < 0) {
		return TC_ACT_OK;
	}

	__u16 sport = bpf_ntohs(udph->source);
	__u16 dport = bpf_ntohs(udph->dest);

	if (!port_in_range(cfg->port_lower, cfg->port_upper, sport, dport)) {
		return TC_ACT_OK;
	}

	if (!ipv4_matches(iph->saddr, iph->daddr)) {
		return TC_ACT_OK;
	}

	if (!is_dns_query(hc)) {
		return TC_ACT_OK;
	}

	if (mv) {
		__sync_fetch_and_add(&mv->dns_matched, 1);
	}

	int error_type = get_error_type(cfg->flags);
	if (error_type == DNS_RCODE_NOERROR) {
		return TC_ACT_OK;
	}

	return inject_or_drop(skb, eth_offset, ip_offset, udp_offset, error_type, 0, mv);
}

static __always_inline int process_ipv6(struct __sk_buff *skb, struct hdr_cursor *hc, __u32 eth_offset, __u32 ip_offset,
										struct config_value *cfg, struct metrics_value *mv)
{
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	int ip_proto;
	__u32 udp_offset;

	if (mv) {
		__sync_fetch_and_add(&mv->ipv6, 1);
	}

	ip_proto = parse_ipv6hdr(hc, &ip6h);
	if (ip_proto < 0) {
		return TC_ACT_OK;
	}

	// IPv6 extension headers are not walked. If present, nexthdr will be the
	// extension header type (not IPPROTO_UDP), so this check causes the packet
	// to pass through unmodified.
	if (ip_proto != IPPROTO_UDP) {
		return TC_ACT_OK;
	}

	udp_offset = ip_offset + sizeof(struct ipv6hdr);

	if (parse_udphdr(hc, &udph) < 0) {
		return TC_ACT_OK;
	}

	__u16 sport = bpf_ntohs(udph->source);
	__u16 dport = bpf_ntohs(udph->dest);

	if (!port_in_range(cfg->port_lower, cfg->port_upper, sport, dport)) {
		return TC_ACT_OK;
	}

	if (!ipv6_matches(&ip6h->saddr, &ip6h->daddr)) {
		return TC_ACT_OK;
	}

	if (!is_dns_query(hc)) {
		return TC_ACT_OK;
	}

	if (mv) {
		__sync_fetch_and_add(&mv->dns_matched, 1);
	}

	int error_type = get_error_type(cfg->flags);
	if (error_type == DNS_RCODE_NOERROR) {
		return TC_ACT_OK;
	}

	return inject_or_drop(skb, eth_offset, ip_offset, udp_offset, error_type, 1, mv);
}

static __always_inline int process(struct __sk_buff *skb)
{
	struct hdr_cursor hc;
	struct ethhdr *eth;
	struct geniphdr *geniph;
	int eth_proto;
	__u32 eth_offset = 0;
	__u32 ip_offset = 0;

	struct config_value *cfg = get_config();
	if (!cfg) {
		return TC_ACT_OK;
	}

	__u32 mkey = 0;
	struct metrics_value *mv = bpf_map_lookup_elem(&metrics_map, &mkey);
	if (mv) {
		__sync_fetch_and_add(&mv->seen, 1);
	}

	hc.pos = (void *)(long)skb->data;
	hc.data_end = (void *)(long)skb->data_end;

	eth_proto = parse_ethhdr(&hc, &eth);
	if (eth_proto >= 0) {
		ip_offset = sizeof(struct ethhdr);
	}

	if (eth_proto < 0) {
		int ip_version = parse_geniphdr(&hc, &geniph);
		if (ip_version == 4) {
			eth_proto = bpf_htons(ETH_P_IP);
		} else if (ip_version == 6) {
			eth_proto = bpf_htons(ETH_P_IPV6);
		} else {
			return TC_ACT_OK;
		}
	}

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		return process_ipv4(skb, &hc, eth_offset, ip_offset, cfg, mv);
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		return process_ipv6(skb, &hc, eth_offset, ip_offset, cfg, mv);
	}

	return TC_ACT_OK;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *skb)
{
	return process(skb);
}

char __license[] SEC("license") = "MIT";
