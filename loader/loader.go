// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

//go:build linux

package loader

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/rs/zerolog/log"
	bpf "github.com/steadybit/dns-inject/ebpf"
)

var validErrorTypes = map[string]bool{
	"NXDOMAIN": true,
	"SERVFAIL": true,
	"TIMEOUT":  true,
}

func IsValidErrorType(t string) bool {
	return validErrorTypes[t]
}

type Config struct {
	ErrorTypes []string
	CIDRs      []string
	PortLower  uint16
	PortUpper  uint16
	Interfaces []string
	Hostnames  []string
}

type Metrics struct {
	Seen             uint64 `json:"seen"`
	Ipv4             uint64 `json:"ipv4"`
	Ipv6             uint64 `json:"ipv6"`
	DnsMatched       uint64 `json:"dns_matched"`
	HostnameFiltered uint64 `json:"hostname_filtered"`
	Injected         uint64 `json:"injected"`
	InjectedNxdomain uint64 `json:"injected_nxdomain"`
	InjectedServfail uint64 `json:"injected_servfail"`
	InjectedTimeout  uint64 `json:"injected_timeout"`
}

type Loader struct {
	objs  *bpf.DnsErrorInjectionObjects
	links []link.Link
}

func New() *Loader {
	return &Loader{}
}

func (l *Loader) Load(config Config) error {
	var objs bpf.DnsErrorInjectionObjects
	if err := bpf.LoadDnsErrorInjectionObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	l.objs = &objs

	if err := l.configureMaps(config); err != nil {
		return fmt.Errorf("configure maps: %w", err)
	}

	if err := l.attachPrograms(config.Interfaces); err != nil {
		return fmt.Errorf("attach programs: %w", err)
	}

	return nil
}

func (l *Loader) configureMaps(config Config) error {
	if err := l.configureConfigMap(config); err != nil {
		return err
	}
	if err := l.configureCIDRMap(config); err != nil {
		return fmt.Errorf("configure CIDR maps: %w", err)
	}
	if err := l.configureHostnameMap(config); err != nil {
		return fmt.Errorf("configure hostname map: %w", err)
	}
	return nil
}

func (l *Loader) configureConfigMap(config Config) error {
	flags := bpf.DnsErrorInjectionConfigFlags(0)

	for _, errorType := range config.ErrorTypes {
		switch errorType {
		case "NXDOMAIN":
			flags |= bpf.DnsErrorInjectionConfigFlagsCONFIG_INJECT_NXDOMAIN
		case "SERVFAIL":
			flags |= bpf.DnsErrorInjectionConfigFlagsCONFIG_INJECT_SERVFAIL
		case "TIMEOUT":
			flags |= bpf.DnsErrorInjectionConfigFlagsCONFIG_INJECT_TIMEOUT
		}
	}

	if flags == 0 {
		return fmt.Errorf("no valid DNS error types configured")
	}

	cv := bpf.DnsErrorInjectionConfigValue{
		Flags:     flags,
		PortLower: config.PortLower,
		PortUpper: config.PortUpper,
	}
	if len(config.Hostnames) > 0 {
		cv.HostnameFilterEnabled = 1
	}
	if err := l.objs.ConfigMap.Put(uint32(0), &cv); err != nil {
		return fmt.Errorf("set config: %w", err)
	}
	return nil
}

type lpmKey4 struct {
	Prefixlen uint32
	Addr      [4]byte
}

type lpmKey6 struct {
	Prefixlen uint32
	Addr      [16]byte
}

func (l *Loader) configureCIDRMap(config Config) error {
	log.Info().Int("cidr_count", len(config.CIDRs)).Msg("configuring CIDR maps")

	var v4Count, v6Count int
	for _, cidr := range config.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		if ipNet.IP.To4() != nil {
			v4Count++
		} else {
			v6Count++
		}
	}
	if capacity := int(l.objs.Ipv4CidrMap.MaxEntries()); v4Count > capacity {
		return fmt.Errorf("too many IPv4 CIDRs: %d exceeds the maximum of %d", v4Count, capacity)
	}
	if capacity := int(l.objs.Ipv6CidrMap.MaxEntries()); v6Count > capacity {
		return fmt.Errorf("too many IPv6 CIDRs: %d exceeds the maximum of %d", v6Count, capacity)
	}

	for _, cidr := range config.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}

		ones, _ := ipNet.Mask.Size()

		if ip4 := ipNet.IP.To4(); ip4 != nil {
			key := lpmKey4{Prefixlen: uint32(ones)}
			copy(key.Addr[:], ip4)
			if err := l.objs.Ipv4CidrMap.Put(&key, uint8(1)); err != nil {
				return fmt.Errorf("failed to add IPv4 CIDR %q: %w", cidr, err)
			}
			log.Info().Str("cidr", cidr).Int("prefixlen", ones).Msg("added IPv4 CIDR to LPM trie")
		} else if ip6 := ipNet.IP.To16(); ip6 != nil {
			key := lpmKey6{Prefixlen: uint32(ones)}
			copy(key.Addr[:], ip6)
			if err := l.objs.Ipv6CidrMap.Put(&key, uint8(1)); err != nil {
				return fmt.Errorf("failed to add IPv6 CIDR %q: %w", cidr, err)
			}
			log.Info().Str("cidr", cidr).Int("prefixlen", ones).Msg("added IPv6 CIDR to LPM trie")
		}
	}

	return nil
}

func (l *Loader) configureHostnameMap(config Config) error {
	if len(config.Hostnames) == 0 {
		return nil
	}
	if capacity := int(l.objs.HostnameMap.MaxEntries()); len(config.Hostnames) > capacity {
		return fmt.Errorf("too many hostnames: %d exceeds the maximum of %d", len(config.Hostnames), capacity)
	}
	log.Info().Int("hostname_count", len(config.Hostnames)).Msg("configuring hostname map")

	for _, h := range config.Hostnames {
		key, err := encodeWireName(h)
		if err != nil {
			return fmt.Errorf("encode hostname %q: %w", h, err)
		}
		var bpfKey bpf.DnsErrorInjectionHostnameKey
		copy(bpfKey.Qname[:], key[:])
		if err := l.objs.HostnameMap.Put(&bpfKey, uint8(1)); err != nil {
			return fmt.Errorf("add hostname %q to map: %w", h, err)
		}
		log.Info().Str("hostname", h).Msg("added hostname filter")
	}
	return nil
}

func (l *Loader) attachPrograms(interfaces []string) error {
	if len(interfaces) == 0 {
		return fmt.Errorf("no interfaces specified")
	}

	for _, ifaceName := range interfaces {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
		}

		egressLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   l.objs.EgressProgFunc,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			return fmt.Errorf("failed to attach TCX egress to %s: %w", ifaceName, err)
		}
		l.links = append(l.links, egressLink)

		log.Info().Str("interface", ifaceName).Int("ifindex", iface.Index).Msg("attached via TCX")
	}

	return nil
}

func (l *Loader) Close() error {
	var errs []error
	for _, tcxLink := range l.links {
		errs = append(errs, tcxLink.Close())
	}
	if l.objs != nil {
		errs = append(errs, l.objs.Close())
	}
	return errors.Join(errs...)
}

func (l *Loader) ReadMetrics() (*Metrics, error) {
	if l.objs == nil {
		return nil, fmt.Errorf("eBPF objects not loaded")
	}

	var key uint32
	var mv bpf.DnsErrorInjectionMetricsValue
	if err := l.objs.MetricsMap.Lookup(&key, &mv); err != nil {
		return nil, fmt.Errorf("failed to read metrics: %w", err)
	}

	return &Metrics{
		Seen:             mv.Seen,
		Ipv4:             mv.Ipv4,
		Ipv6:             mv.Ipv6,
		DnsMatched:       mv.DnsMatched,
		HostnameFiltered: mv.HostnameFiltered,
		Injected:         mv.Injected,
		InjectedNxdomain: mv.InjectedNxdomain,
		InjectedServfail: mv.InjectedServfail,
		InjectedTimeout:  mv.InjectedTimeout,
	}, nil
}

func (l *Loader) WriteMetrics(w io.Writer, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	enc := json.NewEncoder(w)

	for {
		select {
		case <-stop:
			l.flushMetrics(enc)
			return
		case <-ticker.C:
			l.flushMetrics(enc)
		}
	}
}

func (l *Loader) flushMetrics(enc *json.Encoder) {
	m, err := l.ReadMetrics()
	if err != nil {
		log.Debug().Err(err).Msg("metrics read failed")
		return
	}
	if err := enc.Encode(m); err != nil {
		log.Debug().Err(err).Msg("metrics write failed")
	}
}
