import subprocess, sys, json, os

SERVER = '127.0.0.1'
PORT = '5353'
BASE_DIG = ['dig', '+short', '+time=5', f'@{SERVER}', f'-p{PORT}']

OUT = []  # list of {name, passed, detail}

def test(name, condition, detail=''):
    OUT.append({'name': name, 'passed': bool(condition), 'detail': detail})
    icon = '✓' if condition else '✗'
    print(f"  {icon} {name}" + (f" — {detail}" if detail else ""))

def dig(domain, qtype='A'):
    try:
        r = subprocess.run(BASE_DIG + [domain, qtype], capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 1

def nslookup(domain):
    try:
        r = subprocess.run(['nslookup', '-timeout=5', f'-port={PORT}', domain, f'{SERVER}'],
                           capture_output=True, text=True, timeout=10)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ''

def run():
    print("=== Functional Tests ===\n")

    out, rc = dig('google.com', 'A')
    test('A record resolution', rc == 0 and out != '' and '.' in out, out.split('\n')[0])

    out, rc = dig('google.com', 'AAAA')
    test('AAAA record resolution', rc == 0 and ':' in out, out.split('\n')[0])

    out, rc = dig('gmail.com', 'MX')
    test('MX record resolution', rc == 0 and out != '', out.split('\n')[0] if out else 'empty')

    out, rc = dig('google.com', 'TXT')
    test('TXT record resolution', rc == 0 and out != '', 'got response' if out else 'empty')

    out, rc = dig('www.wikipedia.org', 'A')
    test('CNAME resolution (www.wikipedia.org)', rc == 0 and out != '', out.split('\n')[0] if out else 'empty')

    out, rc = dig('thisdomaindoesnotexist1234567.com', 'A')
    test('NXDOMAIN for nonexistent domain', rc == 0 and out == '', f'got: {out[:40]}')

    for qtype in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        out, rc = dig('cloudflare.com', qtype)
        test(f'{qtype} record for cloudflare.com', rc == 0, out.split('\n')[0] if out else 'empty')

    out = nslookup('google.com')
    has_addr = 'Address' in out or 'address' in out
    has_ip = any(c.isdigit() for c in out)
    test('nslookup resolution', has_addr and has_ip, 'nslookup returned addresses' if has_ip else 'no addresses')

    dig('github.com', 'A')
    out2, rc2 = dig('github.com', 'A')
    test('Cache hit (same domain twice)', rc2 == 0 and out2 != '', out2.split('\n')[0])

    t0 = __import__('time').time()
    dig('nxdomain-test-xyz-99999.com', 'A')
    t1 = __import__('time').time()
    dig('nxdomain-test-xyz-99999.com', 'A')
    t2 = __import__('time').time()
    first = round((t1 - t0) * 1000, 1)
    second = round((t2 - t1) * 1000, 1)
    test(f'Negative cache speed (first={first}ms, second={second}ms)',
         second < first or second < 50, f'{second}ms')

    out, rc = dig('google.com', 'SOA')
    test('SOA record', rc == 0 and out != '', out.split('\n')[0] if out else 'empty')

    passed = sum(1 for t in OUT if t['passed'])
    failed = sum(1 for t in OUT if not t['passed'])
    print(f"\nResults: {passed} passed, {failed} failed")

    results_data = {
        'suite': 'Functional',
        'total': len(OUT),
        'passed': passed,
        'failed': failed,
        'tests': OUT,
    }
    with open('/tmp/lynx-test-functional.json', 'w') as f:
        json.dump(results_data, f, indent=2)

    return passed, failed

if __name__ == '__main__':
    p, f = run()
    sys.exit(0 if f == 0 else 1)
