// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

#ifndef __PACKET_PARSE_H__
#define __PACKET_PARSE_H__

struct hdr_cursor {
	void *pos;
	void *data_end;
};

struct geniphdr {
	__u8 version;
};

/**
 * parse_ethhdr - Parse Ethernet header and advance cursor
 * @hc: Header cursor containing packet position
 * @ethhdr: Pointer to store the parsed Ethernet header
 *
 * Returns: Next protocol (eth->h_proto) on success, -1 on error
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *hc, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = hc->pos;

	if (hc->pos + sizeof(struct ethhdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*eth);
	*ethhdr = eth;

	return eth->h_proto;
}

/**
 * parse_iphdr - Parse IPv4 header and advance cursor
 * @hc: Header cursor containing packet position
 * @iphdr: Pointer to store the parsed IPv4 header
 *
 * Returns: Next protocol (ip->protocol) on success, -1 on error
 */
static __always_inline int parse_iphdr(struct hdr_cursor *hc, struct iphdr **iphdr)
{
	struct iphdr *ip = hc->pos;

	if (hc->pos + sizeof(struct iphdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*ip);
	*iphdr = ip;

	return ip->protocol;
}

/**
 * parse_ipv6hdr - Parse IPv6 header and advance cursor
 * @hc: Header cursor containing packet position
 * @ipv6hdr: Pointer to store the parsed IPv6 header
 *
 * Returns: Next protocol (ip6->nexthdr) on success, -1 on error
 */
static __always_inline int parse_ipv6hdr(struct hdr_cursor *hc, struct ipv6hdr **ipv6hdr)
{
	struct ipv6hdr *ip6 = hc->pos;

	if (hc->pos + sizeof(struct ipv6hdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*ip6);
	*ipv6hdr = ip6;

	return ip6->nexthdr;
}

/**
 * parse_geniphdr - Parse generic IP header to determine version
 * @hc: Header cursor containing packet position
 * @geniphdr: Pointer to store the parsed generic IP header
 *
 * This is useful for interfaces without Ethernet headers (e.g., tun/raw).
 * Returns: IP version (4 or 6) on success, -1 on error
 */
static __always_inline int parse_geniphdr(struct hdr_cursor *hc, struct geniphdr **geniphdr)
{
	struct geniphdr *ip = hc->pos;

	if (hc->pos + sizeof(struct geniphdr) > hc->data_end) {
		return -1;
	}

	*geniphdr = ip;

	return ip->version >> 4;
}

/**
 * parse_udphdr - Parse UDP header and advance cursor
 * @hc: Header cursor containing packet position
 * @udphdr: Pointer to store the parsed UDP header
 *
 * Returns: UDP header size on success, -1 on error
 */
static __always_inline int parse_udphdr(struct hdr_cursor *hc, struct udphdr **udphdr)
{
	struct udphdr *udp = hc->pos;

	if (hc->pos + sizeof(struct udphdr) > hc->data_end) {
		return -1;
	}

	hc->pos += sizeof(*udp);
	*udphdr = udp;

	return sizeof(*udp);
}

#endif /* __PACKET_PARSE_H__ */
