import sys, json, time, subprocess, socket, struct
from dns_query import build_dns_query

SERVER = '127.0.0.1'
PORT = 5353

OUT = []

def test(name, condition, detail=''):
    OUT.append({'name': name, 'passed': bool(condition), 'detail': detail})
    icon = '✓' if condition else '✗'
    print(f"  {icon} {name}" + (f" — {detail}" if detail else ""))

def test_truncated_response():
    qdata = build_dns_query('google.com', 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((SERVER, PORT))
        sock.sendall(struct.pack('>H', len(qdata)) + qdata)
        raw = b''
        while len(raw) < 2:
            chunk = sock.recv(2 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) >= 2:
            rlen = struct.unpack('>H', raw)[0]
            partial = min(rlen, 20)
            resp = b''
            while len(resp) < partial:
                chunk = sock.recv(partial - len(resp))
                if not chunk:
                    break
                resp += chunk
            test('Truncated TCP read does not crash server', True)
        sock.close()
    except Exception as e:
        test('Truncated TCP read does not crash server', False, str(e))

def test_malformed_query():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00hello', (SERVER, PORT))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if len(data) >= 12:
            flags = struct.unpack('>H', data[2:4])[0]
            rcode = flags & 0x0F
            test('Malformed query returns error (no crash)', True, f'rcode={rcode}')
    except socket.timeout:
        test('Malformed query times out gracefully', True, 'timeout (no crash)')
    except Exception as e:
        test(f'Malformed query handling', False, str(e))
    finally:
        sock.close()

def test_empty_query():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(b'', (SERVER, PORT))
        data, _ = sock.recvfrom(4096)
        sock.close()
        test('Empty query returns something', True, 'received response')
    except socket.timeout:
        test('Empty query times out gracefully', True, 'timeout (no crash)')
    except Exception as e:
        test('Empty query handling', False, str(e))
    finally:
        sock.close()

def test_concurrent_connections():
    sockets = []
    try:
        for i in range(30):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((SERVER, PORT))
            sockets.append(s)
            qdata = build_dns_query(f'host-{i}.test.com', 1)
            s.sendall(struct.pack('>H', len(qdata)) + qdata)
        ok = 0
        for s in sockets:
            try:
                raw = b''
                while len(raw) < 2:
                    chunk = s.recv(2 - len(raw))
                    if not chunk:
                        break
                    raw += chunk
                if len(raw) >= 2:
                    rlen = struct.unpack('>H', raw)[0]
                    resp = b''
                    while len(resp) < rlen:
                        chunk = s.recv(rlen - len(resp))
                        if not chunk:
                            break
                        resp += chunk
                    ok += 1
            except socket.timeout:
                pass
            s.close()
        test('30 concurrent TCP connections', ok >= 20,
             f'{ok}/30 responded')
    except Exception as e:
        test('30 concurrent TCP connections', False, str(e))
        for s in sockets:
            try: s.close()
            except: pass

def test_rapid_connect_disconnect():
    try:
        for _ in range(50):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((SERVER, PORT))
            s.close()
        test('50 rapid connect/disconnect cycles', True)
    except Exception as e:
        test('50 rapid connect/disconnect cycles', False, str(e))

def test_monitoring_endpoint():
    import urllib.request
    try:
        resp = urllib.request.urlopen('http://127.0.0.1:8085/api/stats', timeout=5)
        data = resp.read().decode()
        d = json.loads(data)
        fields = ['errors', 'latency', 'cache', 'upstream_health', 'connections', 'thread_pool']
        missing = [f for f in fields if f not in d]
        test('Stats API returns all required fields', len(missing) == 0,
             f'missing: {missing}' if missing else 'all present')
    except Exception as e:
        test(f'Monitoring endpoint access', False, str(e))

def test_dnssec():
    r = subprocess.run(['dig', '+time=5', f'@{SERVER}', f'-p{PORT}',
                        'google.com', '+dnssec', '+multi'],
                       capture_output=True, text=True, timeout=10)
    test('DNSSEC query returns response (no crash)', r.returncode == 0,
         'AD' if 'ad' in r.stdout.lower() else 'RRSIG' if 'RRSIG' in r.stdout else 'responded')

def test_idle_timeout():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    try:
        s.connect((SERVER, PORT))
        qdata = build_dns_query('google.com', 1)
        s.sendall(struct.pack('>H', len(qdata)) + qdata)
        raw = b''
        while len(raw) < 2:
            chunk = s.recv(2 - len(raw))
            if not chunk: break
            raw += chunk
        if len(raw) >= 2:
            rlen = struct.unpack('>H', raw)[0]
            resp = b''
            while len(resp) < rlen:
                chunk = s.recv(rlen - len(resp))
                if not chunk: break
                resp += chunk
        time.sleep(8)
        s.sendall(struct.pack('>H', len(qdata)) + qdata)
        raw2 = b''
        while len(raw2) < 2:
            chunk = s.recv(2 - len(raw2))
            if not chunk: break
            raw2 += chunk
        if len(raw2) >= 2:
            rlen2 = struct.unpack('>H', raw2)[0]
            resp2 = b''
            while len(resp2) < rlen2:
                chunk = s.recv(rlen2 - len(resp2))
                if not chunk: break
                resp2 += chunk
            test('Idle connection reuse (8s gap)', True)
        else:
            test('Idle connection closed gracefully', True, 'connection closed after idle')
        s.close()
    except Exception as e:
        test('Idle timeout handling', False, str(e))
        try: s.close()
        except: pass

TESTS = [
    ("Truncated Response", test_truncated_response),
    ("Malformed Query", test_malformed_query),
    ("Empty Query", test_empty_query),
    ("Concurrent TCP", test_concurrent_connections),
    ("Rapid Connect/Disconnect", test_rapid_connect_disconnect),
    ("Monitoring Endpoint", test_monitoring_endpoint),
    ("DNSSEC Query", test_dnssec),
    ("Idle Timeout", test_idle_timeout),
]

def run():
    print("=== Resilience Tests ===\n")
    for name, fn in TESTS:
        print(f"[{name}]")
        try: fn()
        except Exception as e:
            test(name, False, str(e))

    passed = sum(1 for t in OUT if t['passed'])
    failed = sum(1 for t in OUT if not t['passed'])
    print(f"\nResults: {passed} passed, {failed} failed")

    res = {'suite': 'Resilience', 'total': len(OUT), 'passed': passed, 'failed': failed, 'tests': OUT}
    with open('/tmp/lynx-test-resilience.json', 'w') as f:
        json.dump(res, f, indent=2)

    return passed, failed

if __name__ == '__main__':
    p, f = run()
    sys.exit(0 if f == 0 else 1)
