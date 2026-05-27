// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package loader

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// hostnameKeySize is the BPF map key size: the RFC 1035 §3.1 wire-format
// limit on a domain name (255 bytes including length octets and the
// terminating zero-length label).
const hostnameKeySize = 255

// hostnameIDNAProfile is a permissive IDNA profile: it maps Unicode to
// ASCII (punycode) for IDN labels but does not reject DNS-valid characters
// like underscores, which appear in SRV (`_sip._tcp.…`), DKIM/DMARC
// (`_dmarc.example.com`), and Kubernetes service-discovery names. Per-label
// length and emptiness are enforced by NormalizeHostname.
var hostnameIDNAProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(true),
	idna.ValidateLabels(false),
	idna.StrictDomainName(false),
)

// NormalizeHostname validates a user-supplied hostname and returns its
// canonical ASCII/lowercase form. It trims one trailing dot, maps Unicode
// to punycode via a permissive IDNA profile, and enforces RFC 1035 length
// limits (≤253 chars total, each label 1..63 chars).
func NormalizeHostname(s string) (string, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("empty hostname")
	}

	ascii, err := hostnameIDNAProfile.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid hostname %q: %w", s, err)
	}
	ascii = strings.ToLower(ascii)

	if len(ascii) > 253 {
		return "", fmt.Errorf("hostname %q exceeds 253 chars", ascii)
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 {
			return "", fmt.Errorf("invalid empty label in %q", ascii)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("invalid label %q in %q (over 63 chars)", label, ascii)
		}
	}

	return ascii, nil
}

// encodeWireName converts a normalized domain name (as produced by
// NormalizeHostname) into its wire-format representation as a fixed-size
// 255-byte buffer, matching the layout the BPF program reads from packets.
// Label/length validation is the caller's responsibility (NormalizeHostname);
// this function returns an error only if the wire form would overflow.
func encodeWireName(name string) ([hostnameKeySize]byte, error) {
	var key [hostnameKeySize]byte
	pos := 0
	for _, label := range strings.Split(name, ".") {
		if pos+1+len(label) >= len(key) {
			return key, fmt.Errorf("hostname %q exceeds 255 bytes wire format", name)
		}
		key[pos] = byte(len(label))
		copy(key[pos+1:], label)
		pos += 1 + len(label)
	}
	key[pos] = 0
	return key, nil
}
