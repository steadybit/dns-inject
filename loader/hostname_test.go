// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package loader

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "ascii passthrough", in: "example.com", want: "example.com"},
		{name: "uppercase lowercased", in: "EXAMPLE.COM", want: "example.com"},
		{name: "mixed case lowercased", in: "Example.Com", want: "example.com"},
		{name: "trailing dot trimmed", in: "example.com.", want: "example.com"},
		{name: "uppercase + trailing dot", in: "EXAMPLE.COM.", want: "example.com"},
		{name: "unicode to punycode", in: "münchen.de", want: "xn--mnchen-3ya.de"},
		{name: "underscore label allowed (DMARC)", in: "_dmarc.example.com", want: "_dmarc.example.com"},
		{name: "underscore label allowed (SRV)", in: "_sip._tcp.example.com", want: "_sip._tcp.example.com"},
		{name: "empty rejected", in: "", wantErr: "empty hostname"},
		{name: "only dot rejected", in: ".", wantErr: "empty hostname"},
		{name: "empty label rejected", in: "foo..bar", wantErr: "invalid empty label"},
		{
			name:    "total length over 253 rejected",
			in:      strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63),
			wantErr: "exceeds 253",
		},
		{
			name:    "label over 63 rejected",
			in:      strings.Repeat("a", 64) + ".com",
			wantErr: "label",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeHostname(tc.in)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEncodeWireName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []byte // first N bytes of the 255-byte key; rest must be zero
		wantErr string
	}{
		{
			name: "single label",
			in:   "example",
			want: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
		},
		{
			name: "two labels",
			in:   "example.com",
			want: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "three labels",
			in:   "test.example.com",
			want: []byte{4, 't', 'e', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name:    "wire form too long rejected",
			in:      strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
			wantErr: "exceeds 255 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := encodeWireName(tc.in)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, key[:len(tc.want)])
			// Bytes past the encoded form must be zero.
			for i := len(tc.want); i < len(key); i++ {
				assert.Zero(t, key[i], "byte %d must be zero", i)
			}
		})
	}
}
