// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/steadybit/dns-inject/loader"
)

type rootOpts struct {
	errorTypes      []string
	cidrs           []string
	portRange       string
	interfaces      []string
	metricsInterval time.Duration
}

func NewRootCmd(version string) *cobra.Command {
	opts := &rootOpts{}

	cmd := &cobra.Command{
		Use:     "dns-inject",
		Short:   "Inject DNS errors using eBPF/TCX",
		Version: version,
		RunE:    opts.run,
	}

	cmd.Flags().StringSliceVarP(&opts.errorTypes, "error-type", "e", nil, "DNS error type to inject (NXDOMAIN, SERVFAIL, TIMEOUT), can be repeated")
	cmd.Flags().StringSliceVarP(&opts.cidrs, "cidr", "c", nil, "target IP CIDR to match, can be repeated (default: 0.0.0.0/0)")
	cmd.Flags().StringVarP(&opts.portRange, "port", "p", "53", "DNS port or port range to intercept (e.g. 53 or 1-65535)")
	cmd.Flags().StringSliceVarP(&opts.interfaces, "interface", "i", nil, "network interface to attach to, can be repeated (default: all non-loopback)")
	cmd.Flags().DurationVarP(&opts.metricsInterval, "metrics-interval", "m", 10*time.Second, "metrics output interval")

	_ = cmd.MarkFlagRequired("error-type")

	return cmd
}

func (opts *rootOpts) run(cmd *cobra.Command, args []string) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	for _, t := range opts.errorTypes {
		if !loader.IsValidErrorType(t) {
			return fmt.Errorf("invalid error type %q, valid: NXDOMAIN, SERVFAIL, TIMEOUT", t)
		}
	}

	if len(opts.cidrs) == 0 {
		opts.cidrs = []string{"0.0.0.0/0", "::/0"}
	}

	portLower, portUpper, err := parsePortRange(opts.portRange)
	if err != nil {
		return err
	}

	if len(opts.interfaces) == 0 {
		discovered, err := discoverInterfaces()
		if err != nil {
			return fmt.Errorf("discover interfaces: %w", err)
		}
		opts.interfaces = discovered
		log.Info().Strs("interfaces", opts.interfaces).Msg("auto-discovered non-loopback interfaces")
	}

	config := loader.Config{
		ErrorTypes: opts.errorTypes,
		CIDRs:      opts.cidrs,
		PortLower:  portLower,
		PortUpper:  portUpper,
		Interfaces: opts.interfaces,
	}

	l := loader.New()
	defer func() {
		if err := l.Close(); err != nil {
			log.Error().Err(err).Msg("cleanup failed")
		}
	}()
	if err := l.Load(config); err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}

	log.Info().
		Strs("error_types", opts.errorTypes).
		Strs("cidrs", opts.cidrs).
		Str("port_range", opts.portRange).
		Strs("interfaces", opts.interfaces).
		Msg("dns-inject started")

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.WriteMetrics(os.Stdout, opts.metricsInterval, stop)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info().Msg("shutting down")
	close(stop)
	<-done

	return nil
}

func discoverInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		names = append(names, iface.Name)
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("no non-loopback interfaces found")
	}

	return names, nil
}

func parsePortRange(s string) (uint16, uint16, error) {
	if parts := strings.SplitN(s, "-", 2); len(parts) == 2 {
		lower, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q: %w", s, err)
		}
		upper, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q: %w", s, err)
		}
		if lower < 1 || upper > 65535 || lower > upper {
			return 0, 0, fmt.Errorf("invalid port range %q: must be 1-%d with lower <= upper", s, 65535)
		}
		return uint16(lower), uint16(upper), nil
	}

	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if port < 1 || port > 65535 {
		return 0, 0, fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	return uint16(port), uint16(port), nil
}
