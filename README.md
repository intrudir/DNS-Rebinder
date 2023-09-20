# DNS-Rebinder
A modified version of cujanovic's dns.py for DNS Rebinding attacks.
https://github.com/cujanovic/SSRF-Testing/blob/master/dns.py

## Usage
```bash
sudo python3 dns-rebinder.py Whitelisted_IP Rebind_IP Server_IP Port Domain
```
- Whitelisted_IP: IP that the target application likes
- Rebind_IP: IP you want to switch to for the rebind attack
- Server_IP: Server you're running the script on
- Port: usually 53
- Domain: Domain you're using to rebind attack.

```bash
sudo python3 dns-rebinder.py 8.8.8.8 127.0.0.1 x.x.x.x 53 attacker.com
```

test it out :)
```bash
dig anything.attacker.com
```

It will resolve to the whitelisted IP first, then the rebind IP on the 2nd(ish) resolve.
![image](https://github.com/intrudir/DNS-Rebinder/assets/24526564/e0c71320-42e9-4099-b56a-befa593950e7)

