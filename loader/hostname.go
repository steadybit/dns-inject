// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package loader

import (
	"fmt"
	"strings"
)

// hostnameKeySize is the BPF map key size: the RFC 1035 §3.1 wire-format
// limit on a domain name (255 bytes including length octets and the
// terminating zero-length label).
const hostnameKeySize = 255

// encodeWireName converts a textual domain name (e.g. "example.com") into
// its wire-format representation as a fixed-size 255-byte buffer, matching
// the layout the BPF program reads from packets. The caller is responsible
// for normalizing case and IDN before calling this function.
func encodeWireName(name string) ([hostnameKeySize]byte, error) {
	var key [hostnameKeySize]byte
	if name == "" {
		return key, fmt.Errorf("empty hostname")
	}
	pos := 0
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return key, fmt.Errorf("invalid label %q in %q", label, name)
		}
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
