// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package cmd

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
		{name: "empty rejected", in: "", wantErr: "empty hostname"},
		{name: "only dot rejected", in: ".", wantErr: "empty hostname"},
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
			got, err := normalizeHostname(tc.in)
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
