# DNS Traffic Replay

A set of Python tools to export DNS query rate patterns from Prometheus and replay them against a DNS server while preserving day‑of‑week and time‑of‑day characteristics.  
Supports offline replay via compact JSON blueprints and direct on‑the‑fly replay from Prometheus.

---

## Scripts

| Script | Description |
|--------|-------------|
| `dns_traffic_blueprint.py` | Export traffic patterns from Prometheus to a portable JSON blueprint. Also includes legacy replay functionality. |
| `traffic_replay.py` | Replay traffic from a blueprint or directly from Prometheus. Includes DNS server test, query‑type distribution, and speed control. |

---

## Requirements

- Python 3.6+
- [Scapy](https://scapy.net/) – live packet transmission (requires root)
- `requests` – Prometheus API
- `numpy` – statistical variance (optional; falls back to `random.gauss`)

```bash
pip install scapy requests numpy
```

---

## `dns_traffic_blueprint.py` – Export Mode

Export a traffic pattern from Prometheus to a JSON blueprint.

```
python3 dns_traffic_blueprint.py --export [options]
```

### Export Options

| Option | Description |
|--------|-------------|
| `--prometheus URL` | Prometheus server URL (default: `http://localhost:9090`). |
| `--instance FILTER` | Instance label filter for `dnsdist_queries` (default: `dnsdist:8083`). |
| `--from TIMESTAMP` | Start of historical time range (RFC3339). |
| `--to TIMESTAMP` | End of historical time range (RFC3339). |
| `--time-offset HOURS` | Shift all timestamps by N hours (e.g., `9` for UTC→JST). |
| `--step MINUTES` | Bucket size in minutes (1,5,15,…). Smaller = higher detail. |
| `--output FILENAME` | Output JSON file (default: `traffic_blueprint.json`). |

**Example:**
```bash
python3 dns_traffic_blueprint.py --export \
    --prometheus http://prometheus.example.com:9090 \
    --from 2026-01-08T05:00:00.000Z \
    --to   2026-01-29T04:59:59.000Z \
    --time-offset 9 \
    --step 1 \
    --output office_pattern_accurate.json
```

---

## `traffic_replay.py` – Replay Mode

Replay traffic from either a blueprint or a live Prometheus query.

```
sudo python3 traffic_replay.py (--blueprint FILE | --prometheus URL ...) [options]
```

### Source Selection (mutually exclusive)

| Option | Description |
|--------|-------------|
| `--blueprint FILE` | Replay from a pre‑exported blueprint JSON file. |
| `--prometheus URL` | Replay directly from Prometheus (requires `--from`/`--to`). |

### Common Replay Options

| Option | Description |
|--------|-------------|
| `--ips FILE` | **Required.** File with one source IP per line. |
| `--domains FILE` | **Required.** File with one domain per line. |
| `--replay-start TIME` | Start time for replay (format: `YYYY-MM-DD HH:MM:SS`). Default: now. |
| `--replay-days DAYS` | Duration of replay in days (default: 7). |
| `--dns-server IP` | Target DNS server IP (default: `8.8.8.8`). |
| `--speed N` | Speed multiplier. Higher = faster replay (default: 1.0). |
| `--variance FACTOR` | Relative variance factor for low‑sample slots (blueprint only, default: 0.15). |
| `--no-smooth` | Disable inter‑packet spacing (send all queries immediately). |
| `--no-dns-test` | Skip DNS server responsiveness pre‑check. |
| `--dry-run` | Simulate only – do not send packets. |
| `--replay` | Actually send packets. **Requires root.** |

### Prometheus‑Specific Options (when using `--prometheus`)

| Option | Description |
|--------|-------------|
| `--from TIMESTAMP` | Start of historical time range (RFC3339). |
| `--to TIMESTAMP` | End of historical time range (RFC3339). |
| `--instance FILTER` | Instance label filter (default: `dnsdist:8083`). |

**Examples:**

**Replay a 14‑day blueprint at normal speed**
```bash
sudo python3 traffic_replay.py \
    --blueprint office_pattern_accurate.json \
    --ips ips.txt --domains domains.txt \
    --replay --dns-server 1.1.1.1 \
    --replay-days 14
```

**Direct replay from Prometheus at 30x speed (dry‑run)**
```bash
python3 traffic_replay.py \
    --prometheus http://localhost:9090 \
    --from 2026-01-08T05:00:00.000Z \
    --to 2026-01-29T04:59:59.000Z \
    --ips ips.txt --domains domains.txt \
    --replay-days 7 --speed 30 --dry-run
```

**Live replay with custom DNS server and variance**
```bash
sudo python3 traffic_replay.py \
    --blueprint office_pattern_accurate.json \
    --ips ips.txt --domains domains.txt \
    --dns-server 10.0.0.53 --variance 0.3 \
    --replay-days 3 --replay
```

---

## Important Notes

- **Root privileges** are required for live packet transmission (Scapy raw IP sockets).  
- The system sends **UDP DNS queries only**. TCP, EDNS, DNSSEC are not simulated.  
- The Prometheus metric `dnsdist_queries` is expected to be a counter; the query uses `rate()` to obtain QPS.  
- The DNS server pre‑check creates a real socket to determine the source IP that will be used. Use `--no-dns-test` if this is unreliable in your environment.  
- Blueprint files are self‑contained (kilobytes) and contain all necessary per‑minute statistics (`qps_mean`, `qps_std`, sample counts). No Prometheus connection is needed for replay.

---

## License

MIT
