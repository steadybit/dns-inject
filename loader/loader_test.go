// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package loader

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name:    "empty string rejected",
			in:      "",
			wantErr: "empty hostname",
		},
		{
			name:    "empty label rejected",
			in:      "foo..bar",
			wantErr: "invalid label",
		},
		{
			name:    "label too long rejected",
			in:      strings.Repeat("a", 64) + ".com",
			wantErr: "invalid label",
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
