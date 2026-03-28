// Compact vmlinux.h replacement for DNS error injection eBPF program.
// Based on cilium/ebpf examples/headers/common.h, extended with
// network protocol structs needed for packet parsing.

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __u16 __sum16;

#include "bpf_helpers.h"

// BPF map types
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC           = 0,
	BPF_MAP_TYPE_HASH             = 1,
	BPF_MAP_TYPE_ARRAY            = 2,
	BPF_MAP_TYPE_PROG_ARRAY       = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH      = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY     = 6,
	BPF_MAP_TYPE_LPM_TRIE         = 11,
	BPF_MAP_TYPE_RINGBUF          = 27,
};

// TC actions
enum tc_action {
	TC_ACT_UNSPEC     = -1,
	TC_ACT_OK         = 0,
	TC_ACT_RECLASSIFY = 1,
	TC_ACT_SHOT       = 2,
	TC_ACT_PIPE       = 3,
	TC_ACT_STOLEN     = 4,
	TC_ACT_QUEUED     = 5,
	TC_ACT_REPEAT     = 6,
	TC_ACT_REDIRECT   = 7,
};

// BPF map update flags
enum {
	BPF_ANY     = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST   = 2,
	BPF_F_LOCK  = 4,
};

// BPF helper flags
#define BPF_F_RECOMPUTE_CSUM (1ULL << 0)
#define BPF_F_INGRESS        (1ULL << 0)

// Ethernet
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_ALEN   6

struct ethhdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	__be16 h_proto;
};

// IPv4
#define IPPROTO_UDP 17

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl: 4;
	__u8 version: 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	__u8 version: 4;
	__u8 ihl: 4;
#else
#error "Unknown byte order"
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

// IPv6
struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	};
};

struct ipv6hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 priority: 4;
	__u8 version: 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	__u8 version: 4;
	__u8 priority: 4;
#else
#error "Unknown byte order"
#endif
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

// UDP
struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

// TC/skb context
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
};
