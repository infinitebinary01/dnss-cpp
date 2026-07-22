<img src="logo.png" alt="Lynx DNS" width="128" align="right">

# Lynx DNS
A high-performance local DNS server that works on any network

## Features

- **Works on any network** — auto-detects best DNS path: getaddrinfo(), raw UDP, or DoH via libcurl
- **Dual-tier caching** — lock-free L1 turbo cache for hot domains + LRU L2 cache with preemptive refresh
- **Auto-tuner** — Kalman-filtered PID controller that adapts thread pool, cache TTLs, and fan-out rates in real-time
- **Latency manager** — urgency-driven control (0-5) with bottleneck detection
- **Monitoring dashboard** — built-in HTTP server with real-time latency/P95/hit-rate gauges
- **Prometheus metrics** — `/metrics` endpoint for integration with monitoring stacks
- **Instant startup** — no connection pool warmup, starts immediately
- **Network adaptation** — re-probes every 60s, adapts to network changes automatically

## Architecture

See [project-map.html](project-map.html) for the full interactive architecture map.

## Dependencies

- C++17 compiler (GCC 9+, Clang 12+)
- CMake 3.15+
- Boost.Asio 1.74+
- OpenSSL 1.1+
- libcurl

## Build

```bash
git clone <repo-url>
cd dnss-cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Quick Start

```bash
# Start lynx — auto-detects DNS path on any network
./build/lynx --config=config.json

# Query it
dig @127.0.0.1 -p 5353 google.com
```

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `--dns_listen_addr` | `:53` | DNS server listen address |
| `--enable_cache` | — | Enable response caching |
| `--log_level` | `info` | Log level (debug/info/warn/error) |
| `--monitoring_listen_addr` | `:8080` | Monitoring dashboard listen address |

## Monitoring

Open `http://localhost:8080` in a browser for the real-time dashboard.

JSON API: `http://localhost:8080/api/stats`
Prometheus: `http://localhost:8080/metrics`

## Changelog

See [CHANGELOG.html](CHANGELOG.html) for the full version history.

## License

MIT
