<img src="logo.png" alt="Lynx DoH DNS" width="128" align="right">

# Lynx DoH DNS
A high-performance DNS-over-HTTPS (DoH) daemon

## Features

- **DNS-to-HTTPS proxy** — resolves DNS queries via encrypted DoH upstreams (Cloudflare, Google, etc.)
- **Dual-tier caching** — lock-free L1 turbo cache for hot domains + LRU L2 cache with preemptive refresh
- **Connection pool** — maintains persistent HTTPS connections with health-checking and auto-scaling
- **Auto-tuner** — Kalman-filtered PID controller that adapts connection count, thread pool, and cache refresh rates in real-time
- **Monitoring dashboard** — built-in HTTP server with real-time latency/P95/hit-rate gauges
- **Prometheus metrics** — `/metrics` endpoint for integration with monitoring stacks
- **Pre-warming** — caches popular domains on startup for instant responsiveness

## Architecture

```
┌─────────┐   UDP/TCP    ┌──────────────┐   HTTPS      ┌──────────┐
│  Client  │◄──────────►│  DnsServer   │─────────────►│ Upstream │
└─────────┘   :53/8053  │  :53/8053    │  (via proxy) │ (DoH)    │
                         └──────┬───────┘              └──────────┘
                                │
                         ┌──────┴───────┐
                         │ CachingResolver│
                         │  L1 Turbo    │
                         │  L2 LRU      │
                         └──────────────┘
```

## Dependencies

- C++17 compiler (GCC 9+, Clang 12+)
- CMake 3.15+
- Boost.Asio 1.74+
- OpenSSL 1.1+

## Build

```bash
git clone <repo-url>
cd lynx
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Quick Start

```bash
# Start with Cloudflare DoH (uses https_proxy from environment if set)
./build/lynx --enable_dns_to_https \
  --https_upstream="https://cloudflare-dns.com/dns-query" \
  --enable_cache \
  --dns_listen_addr=":8053"

# Query it
dig @127.0.0.1 -p 8053 google.com
```

### With config file

```bash
./build/lynx --config=config.json
```

See `--help` for all options.

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `--dns_listen_addr` | `:53` | DNS server listen address |
| `--https_upstream` | `https://dns.google/dns-query` | DoH upstream URL |
| `--enable_dns_to_https` | — | Enable DNS-to-HTTPS proxy |
| `--enable_cache` | — | Enable response caching |
| `--enable_https_to_dns` | — | Enable HTTPS-to-DNS gateway |
| `--fallback_upstream` | `8.8.8.8:53` | Fallback DNS resolver |
| `--log_level` | `info` | Log level (debug/info/warn/error) |
| `--monitoring_listen_addr` | `:8080` | Monitoring dashboard listen address |
| `--proxy` | `$https_proxy` | HTTPS proxy URL |
| `--no_proxy` | `$no_proxy` | Proxy bypass domains |

## Monitoring

Open `http://localhost:8080` in a browser for the real-time dashboard:

- Latency: avg / P95
- Cache: L1 turbo hit rate / L2 main hit rate
- Connection pool utilization
- Thread pool load
- Auto-tuner status

JSON API: `http://localhost:8080/api/stats`
Prometheus: `http://localhost:8080/metrics`

## License

MIT
