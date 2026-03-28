// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	dockernetwork "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
)

var (
	dnsInject *dnsInjectContainer
	dns1      *dnsServer
	dns2      *dnsServer
)

func TestMain(m *testing.M) {
	buildCmd := exec.Command("make", "-C", "..", "build")
	out, err := buildCmd.CombinedOutput()
	if err != nil {
		panic("make build failed: " + string(out))
	}

	env := setupTestEnv()
	dnsInject = env.dnsInject
	dns1 = env.dns1
	dns2 = env.dns2

	exitCode := m.Run()

	env.teardown()
	os.Exit(exitCode)
}

func TestIpv4NonMatchingPortDoesNotAffectDNS(t *testing.T) {
	dnsInject.start(t, "--port", "8888-9999", "--error-type", "NXDOMAIN")

	result := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Equal(t, 0, result.exitCode, "dig should succeed when dns-inject listens on a different port")
	assert.Contains(t, result.output, "ANSWER SECTION")

	dnsInject.stop(t)
}

func TestIpv4TimeoutDropsPackets(t *testing.T) {
	dnsInject.start(t, "--error-type", "TIMEOUT")

	result := dnsInject.dig4(t, testDomain, dns1.atIPv4(), "+timeout=3", "+tries=1")
	assert.NotEqual(t, 0, result.exitCode, "dig should fail with timeout")
	assert.Contains(t, result.output, "timed out")

	dnsInject.stop(t)
}

func TestIpv4CIDRFilterOnlyAffectsMatchingServer(t *testing.T) {
	dnsInject.start(t, "--cidr", dns1.cidrIPv4(), "--error-type", "SERVFAIL")

	resultAffected := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Contains(t, resultAffected.output, "SERVFAIL")

	resultUnaffected := dnsInject.dig4(t, testDomain, dns2.atIPv4())
	assert.Equal(t, 0, resultUnaffected.exitCode, "dig to second DNS should succeed")
	assert.Contains(t, resultUnaffected.output, "ANSWER SECTION")

	dnsInject.stop(t)
}

func TestIpv4InterfaceLoDoesNotAffectEth0(t *testing.T) {
	dnsInject.start(t, "--interface", "lo", "--error-type", "SERVFAIL")

	result := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Equal(t, 0, result.exitCode, "dig should succeed when dns-inject is only on lo")
	assert.Contains(t, result.output, "ANSWER SECTION")

	dnsInject.stop(t)
}

func TestIpv4InterfaceEth0AffectsDNS(t *testing.T) {
	dnsInject.start(t, "--interface", "eth0", "--error-type", "SERVFAIL")

	result := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Contains(t, result.output, "SERVFAIL")

	dnsInject.stop(t)
}

func TestIpv4NxdomainInjection(t *testing.T) {
	dnsInject.start(t, "--error-type", "NXDOMAIN")

	result := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Contains(t, result.output, "NXDOMAIN")

	dnsInject.stop(t)
}

func TestIpv4CombinedErrorTypes(t *testing.T) {
	dnsInject.start(t, "--error-type", "NXDOMAIN", "--error-type", "SERVFAIL", "--error-type", "TIMEOUT")

	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		result := dnsInject.dig4(t, testDomain, dns1.atIPv4(), "+timeout=3", "+tries=1")
		if strings.Contains(result.output, "NXDOMAIN") {
			seen["NXDOMAIN"] = true
		}
		if strings.Contains(result.output, "SERVFAIL") {
			seen["SERVFAIL"] = true
		}
		if strings.Contains(result.output, "timed out") || strings.Contains(result.output, "no servers could be reached") {
			seen["TIMEOUT"] = true
		}
	}

	assert.True(t, seen["NXDOMAIN"], "NXDOMAIN should have been returned at least once")
	assert.True(t, seen["SERVFAIL"], "SERVFAIL should have been returned at least once")
	assert.True(t, seen["TIMEOUT"], "TIMEOUT should have been returned at least once")

	dnsInject.stop(t)
}

func TestIPv6ServfailInjection(t *testing.T) {
	dnsInject.start(t, "--error-type", "SERVFAIL")

	result := dnsInject.dig6(t, testDomain, dns1.atIPv6())
	assert.Contains(t, result.output, "SERVFAIL")

	dnsInject.stop(t)
}

func TestIPv6CIDRFilterOnlyAffectsMatchingServer(t *testing.T) {
	dnsInject.start(t, "--cidr", dns1.cidrIPv6(), "--error-type", "SERVFAIL")

	resultAffected := dnsInject.dig6(t, testDomain, dns1.atIPv6())
	assert.Contains(t, resultAffected.output, "SERVFAIL")

	resultUnaffected := dnsInject.dig6(t, testDomain, dns2.atIPv6())
	assert.Equal(t, 0, resultUnaffected.exitCode, "dig to second DNS should succeed")
	assert.Contains(t, resultUnaffected.output, "ANSWER SECTION")

	dnsInject.stop(t)
}

func TestIpv4CIDRDoesNotAffectIPv6(t *testing.T) {
	dnsInject.start(t, "--cidr", dns1.cidrIPv4(), "--error-type", "SERVFAIL")

	resultV6 := dnsInject.dig6(t, testDomain, dns1.atIPv6())
	assert.Equal(t, 0, resultV6.exitCode, "IPv6 dig should succeed when only IPv4 CIDR is configured")
	assert.Contains(t, resultV6.output, "ANSWER SECTION")

	resultV4 := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Contains(t, resultV4.output, "SERVFAIL", "IPv4 dig should get SERVFAIL")

	dnsInject.stop(t)
}

func TestIpv6CIDRDoesNotAffectIPv4(t *testing.T) {
	dnsInject.start(t, "--cidr", dns1.cidrIPv6(), "--error-type", "SERVFAIL")

	resultV4 := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Equal(t, 0, resultV4.exitCode, "IPv4 dig should succeed when only IPv6 CIDR is configured")
	assert.Contains(t, resultV4.output, "ANSWER SECTION")

	resultV6 := dnsInject.dig6(t, testDomain, dns1.atIPv6())
	assert.Contains(t, resultV6.output, "SERVFAIL", "IPv6 dig should get SERVFAIL")

	dnsInject.stop(t)
}

func TestIPv6NonMatchingPortDoesNotAffect(t *testing.T) {
	dnsInject.start(t, "--port", "8888-9999", "--error-type", "NXDOMAIN")

	result := dnsInject.dig6(t, testDomain, dns1.atIPv6())
	assert.Equal(t, 0, result.exitCode, "dig should succeed when dns-inject listens on a different port")
	assert.Contains(t, result.output, "ANSWER SECTION")

	dnsInject.stop(t)
}

func TestPortRangeAffectsConfiguredRange(t *testing.T) {
	dnsInject.start(t, "--port", "50-60", "--error-type", "SERVFAIL")

	resultAffected := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Contains(t, resultAffected.output, "SERVFAIL", "port 53 should be in range 50-60")

	dnsInject.stop(t)
}

func TestPortRangeDoesNotAffectOutsideRange(t *testing.T) {
	dnsInject.start(t, "--port", "8888-9999", "--error-type", "SERVFAIL")

	resultUnaffected := dnsInject.dig4(t, testDomain, dns1.atIPv4())
	assert.Equal(t, 0, resultUnaffected.exitCode, "port 53 should not be in range 8888-9999")
	assert.Contains(t, resultUnaffected.output, "ANSWER SECTION")

	dnsInject.stop(t)
}

// test environment

const (
	binaryPath    = "../dns-inject"
	testDomain    = "test.example.com"
	ipv4Subnet    = "172.30.0.0/16"
	ipv6Subnet    = "fd00:db8::/64"
	dns1IPv4      = "172.30.0.10"
	dns1IPv6      = "fd00:db8::10"
	dns2IPv4      = "172.30.0.11"
	dns2IPv6      = "fd00:db8::11"
	injectIPv4    = "172.30.0.100"
	injectIPv6    = "fd00:db8::100"
	corefile      = `. {
    hosts {
        1.2.3.4 test.example.com
        fallthrough
    }
    forward . 8.8.8.8
}
`
)

type dnsServer struct {
	container *testcontainers.DockerContainer
	ipv4      string
	ipv6      string
}

func (d *dnsServer) atIPv4() string  { return "@" + d.ipv4 }
func (d *dnsServer) atIPv6() string  { return "@" + d.ipv6 }
func (d *dnsServer) cidrIPv4() string { return d.ipv4 + "/32" }
func (d *dnsServer) cidrIPv6() string { return d.ipv6 + "/128" }

type testEnv struct {
	network   *testcontainers.DockerNetwork
	dnsInject *dnsInjectContainer
	dns1      *dnsServer
	dns2      *dnsServer
}

func (e *testEnv) teardown() {
	ctx := context.Background()
	if e.dnsInject != nil {
		e.dnsInject.terminate()
	}
	if e.dns1 != nil {
		_ = testcontainers.TerminateContainer(e.dns1.container)
	}
	if e.dns2 != nil {
		_ = testcontainers.TerminateContainer(e.dns2.container)
	}
	if e.network != nil {
		_ = e.network.Remove(ctx)
	}
}

func setupTestEnv() *testEnv {
	ctx := context.Background()

	nw, err := network.New(ctx,
		network.WithEnableIPv6(),
		network.WithIPAM(&dockernetwork.IPAM{
			Config: []dockernetwork.IPAMConfig{
				{Subnet: ipv4Subnet},
				{Subnet: ipv6Subnet},
			},
		}),
	)
	if err != nil {
		panic("create network failed: " + err.Error())
	}

	d1 := startCoreDNS(ctx, nw, "dns1", dns1IPv4, dns1IPv6)
	d2 := startCoreDNS(ctx, nw, "dns2", dns2IPv4, dns2IPv6)
	di := startTestContainer(ctx, nw)

	return &testEnv{
		network:   nw,
		dnsInject: di,
		dns1:      &dnsServer{container: d1, ipv4: dns1IPv4, ipv6: dns1IPv6},
		dns2:      &dnsServer{container: d2, ipv4: dns2IPv4, ipv6: dns2IPv6},
	}
}

func startCoreDNS(ctx context.Context, nw *testcontainers.DockerNetwork, alias, ipv4, ipv6 string) *testcontainers.DockerContainer {
	c, err := testcontainers.Run(ctx, "coredns/coredns:1.12.1",
		testcontainers.WithCmd("-conf", "/Corefile"),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			Reader:            strings.NewReader(corefile),
			ContainerFilePath: "/Corefile",
			FileMode:          0o644,
		}),
		network.WithNetwork([]string{alias}, nw),
		testcontainers.WithEndpointSettingsModifier(func(settings map[string]*dockernetwork.EndpointSettings) {
			settings[nw.Name].IPAMConfig = &dockernetwork.EndpointIPAMConfig{
				IPv4Address: ipv4,
				IPv6Address: ipv6,
			}
			settings[nw.Name].IPAddress = ipv4
			settings[nw.Name].GlobalIPv6Address = ipv6
		}),
	)
	if err != nil {
		panic("start coredns failed: " + err.Error())
	}
	return c
}

func startTestContainer(ctx context.Context, nw *testcontainers.DockerNetwork) *dnsInjectContainer {
	c, err := testcontainers.Run(ctx, "alpine:3.20",
		testcontainers.WithCmd("sleep", "infinity"),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			HostFilePath:      binaryPath,
			ContainerFilePath: "/dns-inject",
			FileMode:          0o755,
		}),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.Privileged = true
		}),
		network.WithNetwork([]string{"test-host"}, nw),
		testcontainers.WithEndpointSettingsModifier(func(settings map[string]*dockernetwork.EndpointSettings) {
			settings[nw.Name].IPAMConfig = &dockernetwork.EndpointIPAMConfig{
				IPv4Address: injectIPv4,
				IPv6Address: injectIPv6,
			}
			settings[nw.Name].IPAddress = injectIPv4
			settings[nw.Name].GlobalIPv6Address = injectIPv6
		}),
	)
	if err != nil {
		panic("start test container failed: " + err.Error())
	}

	code, _, err := c.Exec(ctx, []string{"apk", "add", "--update", "bind-tools"})
	if err != nil || code != 0 {
		panic("apk add bind-tools failed")
	}

	return &dnsInjectContainer{container: c}
}

// dnsInjectContainer helpers

type digResult struct {
	exitCode int
	output   string
}

type dnsInjectContainer struct {
	container *testcontainers.DockerContainer
	exited    chan error
}

func (c *dnsInjectContainer) terminate() {
	_ = testcontainers.TerminateContainer(c.container)
}

func (c *dnsInjectContainer) start(t *testing.T, args ...string) {
	t.Helper()
	cmdArgs := append([]string{"/dns-inject"}, args...)
	c.exited = make(chan error, 1)
	ready := make(chan struct{})
	ctx := context.Background()

	go func() {
		e, reader, err := c.execNoWait(ctx, cmdArgs)
		if err != nil {
			c.exited <- err
			close(ready)
			return
		}

		var lines []string
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			lines = append(lines, line)
			if strings.Contains(line, "dns-inject started") {
				close(ready)
			}
		}

		code, err := e.wait(ctx)
		if err != nil {
			c.exited <- err
		} else if code != 0 {
			c.exited <- fmt.Errorf("dns-inject exited with code %d:\n%s", code, strings.Join(lines, "\n"))
		} else {
			c.exited <- nil
		}
	}()

	select {
	case <-ready:
	case err := <-c.exited:
		t.Fatalf("dns-inject failed to start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("dns-inject did not become ready within 10s")
	}
}

func (c *dnsInjectContainer) stop(t *testing.T) {
	t.Helper()
	code, _, err := c.container.Exec(context.Background(), []string{"killall", "dns-inject"})
	require.NoError(t, err)
	assert.Equal(t, 0, code, "killall should succeed")

	select {
	case <-c.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("dns-inject did not exit within 10s after killall")
	}
}

func (c *dnsInjectContainer) dig4(t *testing.T, args ...string) digResult {
	t.Helper()
	return c.dig(t, "-4", args...)
}

func (c *dnsInjectContainer) dig6(t *testing.T, args ...string) digResult {
	t.Helper()
	return c.dig(t, "-6", args...)
}

func (c *dnsInjectContainer) dig(t *testing.T, proto string, args ...string) digResult {
	t.Helper()
	cmdArgs := append([]string{"dig", proto, "+timeout=5", "+tries=1"}, args...)
	code, reader, err := c.container.Exec(context.Background(), cmdArgs)
	require.NoError(t, err)
	out, _ := io.ReadAll(reader)
	output := strings.TrimSpace(string(out))
	t.Logf("dig %s %s → exit=%d output=%s", proto, strings.Join(args, " "), code, output)
	return digResult{exitCode: code, output: output}
}

type execNoWait struct {
	cli      client.APIClient
	response container.ExecCreateResponse
}

func (e *execNoWait) wait(ctx context.Context) (int, error) {
	for {
		execResp, err := e.cli.ContainerExecInspect(ctx, e.response.ID)
		if err != nil {
			return 0, fmt.Errorf("container exec inspect: %w", err)
		}
		if !execResp.Running {
			return execResp.ExitCode, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *dnsInjectContainer) execNoWait(ctx context.Context, cmd []string, options ...tcexec.ProcessOption) (*execNoWait, io.Reader, error) {
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		panic(err)
	}

	cli := (provider.(*testcontainers.DockerProvider)).Client()

	processOptions := tcexec.NewProcessOptions(cmd)
	for _, o := range options {
		o.Apply(processOptions)
	}

	response, err := cli.ContainerExecCreate(ctx, c.container.ID, processOptions.ExecConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("container exec create: %w", err)
	}

	hijack, err := cli.ContainerExecAttach(ctx, response.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("container exec attach: %w", err)
	}

	processOptions.Reader = hijack.Reader
	for _, o := range options {
		o.Apply(processOptions)
	}

	return &execNoWait{cli: cli, response: response}, processOptions.Reader, nil
}
