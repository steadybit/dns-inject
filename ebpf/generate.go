// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type metrics_value -type config_value -type config_flags DnsErrorInjection dns_error_injection.c -- -I. -Iheaders
