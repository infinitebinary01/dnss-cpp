import sys, json, copy
from dns_query import run_load_test, print_results, query_dns

DOMAINS = [
    'google.com', 'cloudflare.com', 'github.com', 'stackoverflow.com',
    'amazon.com', 'youtube.com', 'reddit.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'wikipedia.org', 'linkedin.com',
    'bing.com', 'facebook.com', 'twitter.com', 'instagram.com',
]

OUT = []

def result(name, data, passed=None):
    if passed is None:
        passed = data.get('errors', 1) == 0 or data.get('error_rate', 100) < 20
    OUT.append({'name': name, 'passed': bool(passed), 'data': data})

def test_baseline_latency():
    """Cold cache: first query to unique domains. Measures upstream round-trip."""
    cold = [f'cold-{i}.bench-test-xyz.com' for i in range(10)]
    latencies = []
    for d in cold:
        _, elapsed = query_dns(d)
        if _ is not None:
            latencies.append(elapsed * 1000)
    if latencies:
        avg = sum(latencies) / len(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        d = {'avg_ms': round(avg, 2), 'p95_ms': round(p95, 2),
             'min_ms': round(min(latencies), 2), 'max_ms': round(max(latencies), 2)}
        result('Baseline Latency (cold cache, UDP)', d, passed=avg < 500)
        print(f"    avg={avg:.1f}ms  p95={p95:.1f}ms  min={min(latencies):.1f}ms  max={max(latencies):.1f}ms")
        print(f"    (cold cache = upstream RTT, expected ~50-200ms via proxy)")

def test_cache_hit_latency():
    """Warm cache: sub-millisecond is the goal for a local resolver."""
    for d in DOMAINS[:3]:
        for _ in range(5):
            query_dns(d)
    latencies = []
    for _ in range(200):
        d = DOMAINS[_ % len(DOMAINS)]
        _, elapsed = query_dns(d)
        if _ is not None:
            latencies.append(elapsed * 1000)
    if latencies:
        avg = sum(latencies) / len(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        d = {'avg_ms': round(avg, 2), 'p95_ms': round(p95, 2),
             'min_ms': round(min(latencies), 2), 'max_ms': round(max(latencies), 2)}
        result('Cache Hit Latency (UDP)', d, passed=avg < 1)
        print(f"    avg={avg:.3f}ms  p95={p95:.3f}ms  min={min(latencies):.3f}ms  max={max(latencies):.3f}ms")

def test_udp_throughput():
    """High-concurrency UDP cache hit throughput. Python GIL limits ~3K QPS —
    the server can do much more, but this proves it handles concurrent load."""
    for d in DOMAINS:
        query_dns(d)
        query_dns(d)
    r = run_load_test(DOMAINS * 3, concurrency=20, queries_per_domain=5,
                      timeout=5, use_tcp=False)
    result('UDP Throughput (20c x 240 queries)', copy.deepcopy(r),
           passed=r['error_rate'] < 2 and r['qps'] > 2000)
    print_results("UDP", r)

def test_udp_burst():
    """Short burst of UDP queries to measure peak throughput."""
    burst = [f'burst-{i}.perf-test.com' for i in range(50)]
    for d in burst:
        query_dns(d)
    r = run_load_test(burst, concurrency=20, queries_per_domain=10,
                      timeout=5, use_tcp=False)
    result('UDP Burst (20c x 500 queries)', copy.deepcopy(r),
           passed=r['error_rate'] < 5 and r['qps'] > 1500)
    print_results("UDP", r)

def test_concurrent_cached():
    """Cached domains through both TCP and UDP."""
    r = run_load_test(DOMAINS, concurrency=12, queries_per_domain=8, timeout=5, use_tcp=False)
    result('UDP Concurrent (cached domains)', copy.deepcopy(r), passed=r['error_rate'] < 15)
    print_results("UDP", r)
    r2 = run_load_test(DOMAINS, concurrency=12, queries_per_domain=8, timeout=5, use_tcp=True)
    result('TCP Concurrent (cached domains)', copy.deepcopy(r2), passed=r2['error_rate'] < 5)
    print_results("TCP", r2)

def test_cache_miss_flood():
    """Cache miss: each query must go upstream. Measures thread pool saturation."""
    uniq = [f'miss-{i}.flood-test.com' for i in range(20)]
    r = run_load_test(uniq, concurrency=4, queries_per_domain=1, timeout=8, use_tcp=False)
    result('Cache Miss Flood (UDP, 4c x 20)', copy.deepcopy(r), passed=r['error_rate'] < 30)
    print_results("UDP", r)
    if r['error_rate'] >= 30:
        print(f"    Note: cache misses saturate thread pool — expected (each miss = upstream RTT)")

def test_backpressure_limits():
    """Push past capacity: verify backpressure kicks in, not crashes."""
    domains = [f'bp-{i}.overload-test.com' for i in range(100)]
    r = run_load_test(domains, concurrency=20, queries_per_domain=1, timeout=5, use_tcp=True)
    result('Backpressure (beyond capacity)', copy.deepcopy(r), passed=r['error_rate'] < 60)
    print_results("TCP", r)
    print(f"    {'✓' if r['error_rate'] < 60 else '✗'} Error rate < 60% (backpressure expected)")

def test_sustained_qps():
    """Sustained load: mix of cached domains, UDP primary."""
    test_domains = DOMAINS * 3
    r = run_load_test(test_domains, concurrency=20, queries_per_domain=5, timeout=5, use_tcp=False)
    result('Sustained QPS (UDP, 20c mixed)', copy.deepcopy(r),
           passed=r['error_rate'] < 5 and r['qps'] > 2000)
    print_results("UDP", r)

def test_cache_efficiency():
    """Warm cache, all hits, measure true cache throughput."""
    for d in DOMAINS:
        query_dns(d)
    r = run_load_test(DOMAINS * 3, concurrency=8, queries_per_domain=1, timeout=3, use_tcp=False)
    result('Cache Efficiency (warm, UDP)', copy.deepcopy(r),
           passed=r['error_rate'] < 5 and r['avg_ms'] < 1)
    print_results("UDP", r)

def test_tcp_cache_efficiency():
    """Warm cache via TCP. TCP adds connection overhead but should still be fast."""
    for d in DOMAINS:
        query_dns(d)
    r = run_load_test(DOMAINS * 3, concurrency=8, queries_per_domain=1, timeout=3, use_tcp=True)
    result('Cache Efficiency (warm, TCP)', copy.deepcopy(r),
           passed=r['error_rate'] < 5 and r['avg_ms'] < 10)
    print_results("TCP", r)

def test_mixed_tcp_udp():
    """Realistic mix: UDP primary, TCP fallback."""
    domains = DOMAINS[:8]
    r_udp = run_load_test(domains, concurrency=20, queries_per_domain=10, timeout=5, use_tcp=False)
    result('Mixed UDP (cached)', copy.deepcopy(r_udp), passed=r_udp['error_rate'] < 15)
    print_results("UDP", r_udp)
    r_tcp = run_load_test(domains, concurrency=8, queries_per_domain=5, timeout=5, use_tcp=True)
    result('Mixed TCP (cached)', copy.deepcopy(r_tcp), passed=r_tcp['error_rate'] < 5)
    print_results("TCP", r_tcp)

TESTS = [
    ("Baseline Latency", test_baseline_latency),
    ("Cache Hit Latency", test_cache_hit_latency),
    ("UDP Throughput", test_udp_throughput),
    ("UDP Burst", test_udp_burst),
    ("Concurrent Cached", test_concurrent_cached),
    ("Cache Miss Flood", test_cache_miss_flood),
    ("Backpressure Limits", test_backpressure_limits),
    ("Sustained QPS", test_sustained_qps),
    ("Cache Efficiency", test_cache_efficiency),
    ("TCP Cache Efficiency", test_tcp_cache_efficiency),
    ("Mixed TCP+UDP", test_mixed_tcp_udp),
]

def run():
    print("=== Performance Tests ===\n")
    for name, fn in TESTS:
        print(f"\n[{name}]")
        try:
            fn()
        except Exception as e:
            print(f"  ✗ TEST FAILED: {e}")
            OUT.append({'name': name, 'passed': False, 'data': {'error': str(e)}})

    passed = sum(1 for t in OUT if t['passed'])
    failed = sum(1 for t in OUT if not t['passed'])
    print(f"\nResults: {passed} passed, {failed} failed")

    res = {'suite': 'Performance', 'total': len(OUT), 'passed': passed, 'failed': failed, 'tests': OUT}
    with open('/tmp/lynx-test-performance.json', 'w') as f:
        json.dump(res, indent=2, fp=f)

    return passed, failed

if __name__ == '__main__':
    p, f = run()
    sys.exit(0 if f == 0 else 1)
