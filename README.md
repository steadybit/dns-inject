# dns-inject

A standalone eBPF-based DNS error injection tool. It attaches to network interfaces via [TCX](https://docs.kernel.org/bpf/tcx.html) (Linux 6.6+) and intercepts DNS traffic to inject configurable error responses.

## How It Works

dns-inject loads a compiled eBPF program that inspects DNS packets on the specified network interfaces. Matching packets are modified to return DNS error responses (NXDOMAIN, SERVFAIL) or dropped (TIMEOUT). The tool stays running for the duration of the injection and writes metrics as JSON lines to stdout. When stopped via SIGINT/SIGTERM, the eBPF programs are automatically detached by the kernel.

## Usage

```
dns-inject [flags]

Flags:
  -e, --error-type strings          DNS error type to inject (NXDOMAIN, SERVFAIL, TIMEOUT), can be repeated
  -c, --cidr strings                Target IP CIDR to match, can be repeated (default: 0.0.0.0/0)
  -p, --port string                 DNS port or range to intercept, e.g. 53 or 1-65535 (default: 53)
  -i, --interface strings           Network interface to attach to, can be repeated (default: all non-loopback)
  -n, --hostname strings            Target DNS hostname to match exactly (case-insensitive; underscores and IDN/Unicode names allowed, e.g. _dmarc.example.com or _sip._tcp.example.com), can be repeated
  -m, --metrics-interval duration   Metrics output interval (default: 10s)
  -h, --help                        Help
  -v, --version                     Version
```

### Examples

Inject NXDOMAIN errors for all DNS traffic on eth0:

```bash
dns-inject -e NXDOMAIN -i eth0
```

Inject random NXDOMAIN or SERVFAIL errors targeting a specific container IP:

```bash
dns-inject -e NXDOMAIN -e SERVFAIL -c 172.17.0.2/32 -i docker0
```

Simulate DNS timeouts on a custom DNS port:

```bash
dns-inject -e TIMEOUT -p 5353
```

Inject NXDOMAIN only for `example.com`, leaving every other DNS query unchanged:

```bash
dns-inject -e NXDOMAIN --hostname example.com
```

## Requirements

- **Linux kernel 6.6+** (for TCX support)
- **CAP_BPF**, **CAP_NET_ADMIN** capabilities (or root)

## Building

### Prerequisites

- Go 1.25+
- [goreleaser](https://goreleaser.com/)
- clang and llvm (for eBPF compilation)

On macOS:

```bash
brew install llvm
```

Make sure `llvm-strip` and `clang` are on your PATH, e.g.:

```bash
export PATH="$(brew --prefix llvm)/bin:$PATH"
```

### Build

```bash
make build
```

This runs goreleaser which first generates the eBPF objects from C source via `go generate`, then cross-compiles the binary for linux/amd64 and linux/arm64.

### Regenerate eBPF Objects Only

```bash
make generate
```

### Run Checks

```bash
make audit
```

Runs formatting checks, `go vet`, `staticcheck`, tests, and module verification.

## Metrics Output

dns-inject writes one JSON line per metrics interval to stdout:

```json
{"seen":1042,"ipv4":980,"ipv6":62,"dns_matched":15,"hostname_filtered":3,"injected":12,"injected_nxdomain":8,"injected_servfail":4,"injected_timeout":0}
```

| Field              | Description                              |
|--------------------|------------------------------------------|
| `seen`             | Total packets seen                       |
| `ipv4`             | IPv4 packets                             |
| `ipv6`             | IPv6 packets                             |
| `dns_matched`      | DNS packets matching target CIDRs/ports  |
| `hostname_filtered`| DNS queries skipped because the qname did not match `--hostname` |
| `injected`         | Total error responses injected           |
| `injected_nxdomain`| NXDOMAIN responses injected              |
| `injected_servfail`| SERVFAIL responses injected              |
| `injected_timeout` | Packets dropped to simulate timeout      |

`hostname_filtered` is a subset of `dns_matched`: the hostname check runs
*after* CIDR/port matching, so the relationship is
`dns_matched ≥ hostname_filtered + injected`. Only the first qname in the
question section is matched; DNS name compression in queries (rare in
practice) is not followed.

## License

MIT - see [LICENSE](LICENSE).
