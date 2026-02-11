#!/usr/bin/env python3
"""
DNS Traffic Pattern Replay Script with Day-of-Week Alignment
Replays traffic matching the same day-of-week and time-of-day pattern
Supports both Prometheus querying and blueprint file replay.

Enhancements:
- Realistic query type distribution (A, AAAA, MX, TXT, CNAME)
- Automatic DNS server responsiveness test before live replay
- Fixed DNS test: uses actual local source IP, not a dummy
"""

import requests
import json
import time
import random
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import IP, UDP, DNS, DNSQR, send, sr1
import argparse
import sys
import os
import socket

# Optional numpy for normal distribution (fallback to random.gauss)
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

class DNSTrafficReplayerAligned:
    def __init__(self, prometheus_url=None, start_time=None, end_time=None,
                 source_ips=None, domains=None, instance_filter='dnsdist:8083',
                 blueprint_file=None):
        self.prometheus_url = prometheus_url
        self.start_time = start_time
        self.end_time = end_time
        self.source_ips = source_ips
        self.domains = domains
        self.instance_filter = instance_filter
        self.blueprint_file = blueprint_file

        self.traffic_pattern = []
        self.pattern_by_dow_hour = defaultdict(list)  # (dow, hour) -> list of patterns
        self.bucket_duration_sec = 60
        self.blueprint_mode = False
        self.blueprint_source_start_date = None
        self.skip_dns_test = False

    def load_blueprint(self):
        if not self.blueprint_file:
            return False
        try:
            with open(self.blueprint_file, 'r') as f:
                blueprint = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load blueprint: {e}")
            return False
        self.blueprint_mode = True
        self.blueprint = blueprint
        meta = blueprint.get('metadata', {})
        step_minutes = meta.get('step_minutes', 1)
        self.bucket_duration_sec = step_minutes * 60
        source_start = meta.get('source_start', '')
        if source_start:
            try:
                dt = datetime.fromisoformat(source_start.replace('Z', '+00:00'))
                self.blueprint_source_start_date = dt.date()
            except:
                self.blueprint_source_start_date = datetime.now().date()
        else:
            self.blueprint_source_start_date = datetime.now().date()
        print(f"[+] Loaded blueprint: {self.blueprint_file}")
        print(f"[+] Created: {meta.get('created', 'unknown')}")
        print(f"[+] Source duration: {meta.get('duration_days', 0):.1f} days")
        print(f"[+] Bucket duration: {step_minutes} minute(s) ({self.bucket_duration_sec} sec)")

        patterns = blueprint.get('patterns', {})
        dow_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        for slot_key, data in patterns.items():
            dow = data['dow']
            hour = data['hour']
            minute = data['minute']
            pattern_entry = {
                'dow': dow,
                'hour': hour,
                'minute': minute,
                'queries_per_sec': data['qps_mean'],
                'queries_in_bucket': data['qps_mean'] * self.bucket_duration_sec,
                'bucket_duration_sec': self.bucket_duration_sec,
                'samples': data['samples'],
                'qps_mean': data['qps_mean'],
                'qps_std': data['qps_std'],
                'datetime': datetime.combine(self.blueprint_source_start_date,
                                             datetime.min.time().replace(hour=hour, minute=minute)),
                'dow_name': dow_names[dow]
            }
            key = (dow, hour)
            self.pattern_by_dow_hour[key].append(pattern_entry)
        summary = blueprint.get('summary', {})
        print(f"[+] Loaded {len(self.pattern_by_dow_hour)} hour patterns")
        print(f"[+] Average QPS: {summary.get('avg_qps', 0):.2f}")
        print(f"[+] 95th percentile: {summary.get('p95_qps', 0):.2f}")
        return True

    def test_prometheus_connection(self):
        url = f"{self.prometheus_url}/api/v1/query"
        params = {'query': 'up'}
        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
            if data.get('status') == 'success':
                print(f"[+] Prometheus connection OK: {self.prometheus_url}")
                return True
            else:
                print(f"[!] Prometheus returned status: {data.get('status')}")
                return False
        except Exception as e:
            print(f"[!] Error connecting to Prometheus: {e}")
            return False

    def query_prometheus(self, query, start, end, step='60s'):
        url = f"{self.prometheus_url}/api/v1/query_range"
        params = {'query': query, 'start': start, 'end': end, 'step': step}
        try:
            response = requests.get(url, params=params, timeout=30)
            if response.status_code != 200:
                try:
                    data = response.json()
                    print(f"[!] HTTP {response.status_code}: {data}")
                except:
                    print(f"[!] HTTP {response.status_code}: {response.text[:200]}")
                return None
            return response.json()
        except Exception as e:
            print(f"[!] Query error: {e}")
            return None

    def parse_timestamp(self, ts_string):
        dt = datetime.fromisoformat(ts_string.replace('Z', '+00:00'))
        return dt.timestamp()

    def analyze_traffic_pattern(self):
        if self.blueprint_file:
            return self.load_blueprint()
        print("[+] Analyzing DNS traffic patterns from Prometheus...")
        if not self.test_prometheus_connection():
            print("[!] Please ensure Prometheus is running and accessible")
            return False
        start_ts = self.parse_timestamp(self.start_time)
        end_ts = self.parse_timestamp(self.end_time)
        duration = end_ts - start_ts
        max_points = 10000
        min_step_seconds = int(duration / max_points)
        if min_step_seconds < 60:
            step = '60s'
            step_seconds = 60
        else:
            step_minutes = (min_step_seconds // 60) + 1
            step = f'{step_minutes}m'
            step_seconds = step_minutes * 60
        self.bucket_duration_sec = step_seconds
        expected_points = int(duration / step_seconds)
        print(f"\n[+] Querying metrics from {self.start_time} to {self.end_time}")
        print(f"[+] Duration: {duration / 86400:.1f} days")
        print(f"[+] Using step: {step} (expected ~{expected_points} points)")

        queries_query = f'sum(rate(dnsdist_queries{{instance=~"{self.instance_filter}"}}[5m]))'
        queries_data = self.query_prometheus(queries_query, start_ts, end_ts, step)
        if not queries_data or queries_data.get('status') != 'success':
            print("[+] Trying without instance filter...")
            queries_query = 'sum(rate(dnsdist_queries[5m]))'
            queries_data = self.query_prometheus(queries_query, start_ts, end_ts, step)
        if not queries_data or queries_data.get('status') != 'success':
            print("[!] Failed to get queries data from Prometheus")
            return False

        queries_results = queries_data.get('data', {}).get('result', [])
        print(f"[+] Found {len(queries_results)} query series")
        if not queries_results:
            print("[!] No data found")
            return False

        raw_pattern = []
        for series in queries_results:
            values = series.get('values', [])
            print(f"[+] Processing {len(values)} data points")
            for timestamp, value in values:
                try:
                    rate_per_sec = float(value)
                    queries_in_bucket = rate_per_sec * step_seconds
                    dt = datetime.fromtimestamp(float(timestamp))
                    raw_pattern.append({
                        'timestamp': float(timestamp),
                        'datetime': dt,
                        'dow': dt.weekday(),
                        'dow_name': dt.strftime('%A'),
                        'hour': dt.hour,
                        'minute': dt.minute,
                        'queries_per_sec': rate_per_sec,
                        'queries_in_bucket': queries_in_bucket,
                        'bucket_duration_sec': step_seconds
                    })
                except (ValueError, TypeError):
                    continue

        if not raw_pattern:
            print("[!] No valid data points")
            return False

        self.traffic_pattern = sorted(raw_pattern, key=lambda x: x['timestamp'])
        for pattern in self.traffic_pattern:
            dow = pattern['dow']
            hour = pattern['hour']
            key = (dow, hour)
            self.pattern_by_dow_hour[key].append(pattern)

        queries_per_min = [p['queries_in_bucket'] / (p['bucket_duration_sec'] / 60) for p in self.traffic_pattern]
        print(f"\n[+] Pattern Analysis:")
        print(f"    - Total data points: {len(self.traffic_pattern)}")
        print(f"    - Date range: {self.traffic_pattern[0]['datetime'].strftime('%Y-%m-%d %H:%M')} to {self.traffic_pattern[-1]['datetime'].strftime('%Y-%m-%d %H:%M')}")
        print(f"    - Average rate: {sum(queries_per_min)/len(queries_per_min):.2f} queries/min")
        print(f"    - Max rate: {max(queries_per_min):.2f} queries/min")
        print(f"    - Min rate: {min(queries_per_min):.2f} queries/min")
        print(f"\n[+] Pattern by Day of Week:")
        dow_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        for dow in range(7):
            dow_data = [p for p in self.traffic_pattern if p['dow'] == dow]
            if dow_data:
                avg_rate = sum(p['queries_in_bucket'] for p in dow_data) / len(dow_data)
                print(f"    - {dow_names[dow]}: {len(dow_data)} samples, avg {avg_rate:.2f} queries/bucket")
        return True

    def test_dns_server(self, dns_server, timeout=2):
        """Send a test query to verify DNS server is reachable and responds"""
        print(f"[*] Testing DNS server {dns_server}...", end='', flush=True)

        # Get the local IP that will be used to reach the DNS server
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((dns_server, 53))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "0.0.0.0"  # fallback – may still fail

        test_domain = "example.com"
        packet = self.generate_dns_packet(local_ip, test_domain, dns_server)

        try:
            reply = sr1(packet, timeout=timeout, verbose=False)
            if reply and reply.haslayer(DNS) and reply[DNS].qr == 1:
                print(" OK (response received)")
                return True
            else:
                print(" FAILED (no valid DNS response)")
                return False
        except Exception as e:
            print(f" ERROR ({e})")
            return False

    def generate_replay_schedule(self, replay_start_time=None, replay_duration_days=7,
                                 variance_factor=0.15):
        if not self.pattern_by_dow_hour and not self.blueprint_mode:
            print("[!] No traffic pattern loaded")
            return None
        if replay_start_time is None:
            replay_start_time = datetime.now()
        print(f"\n[+] Generating Replay Schedule:")
        print(f"    - Replay start: {replay_start_time.strftime('%Y-%m-%d %H:%M:%S %A')}")
        print(f"    - Duration: {replay_duration_days} days")
        if self.blueprint_mode:
            print(f"    - Variance factor: ±{variance_factor*100:.0f}%")
        schedule = []
        current_time = replay_start_time
        end_time = replay_start_time + timedelta(days=replay_duration_days)
        bucket_duration = self.bucket_duration_sec
        while current_time < end_time:
            dow = current_time.weekday()
            hour = current_time.hour
            minute = current_time.minute
            if self.blueprint_mode:
                key = (dow, hour)
                matching_patterns = self.pattern_by_dow_hour.get(key, [])
                if matching_patterns:
                    closest = min(matching_patterns,
                                  key=lambda p: abs(p['minute'] - minute))
                    base_queries = closest['qps_mean'] * bucket_duration
                    std = closest.get('qps_std', 0)
                    if closest.get('samples', 1) > 1 and std > 0:
                        if HAS_NUMPY:
                            variance = np.random.normal(0, std * bucket_duration)
                        else:
                            variance = random.gauss(0, std * bucket_duration)
                    else:
                        if HAS_NUMPY:
                            variance = np.random.normal(0, base_queries * variance_factor)
                        else:
                            variance = random.gauss(0, base_queries * variance_factor)
                    queries_in_bucket = max(0, base_queries + variance)
                    if random.random() < 0.05:
                        spike_factor = random.uniform(1.2, 2.0)
                        queries_in_bucket *= spike_factor
                    source_datetime = closest['datetime']
                    source_dow_name = closest['dow_name']
                else:
                    queries_in_bucket = 0
                    source_datetime = None
                    source_dow_name = None
                schedule.append({
                    'replay_time': current_time,
                    'dow': dow,
                    'dow_name': current_time.strftime('%A'),
                    'hour': hour,
                    'minute': minute,
                    'queries_in_bucket': queries_in_bucket,
                    'bucket_duration_sec': bucket_duration,
                    'source_datetime': source_datetime,
                    'source_dow_name': source_dow_name
                })
            else:
                key = (dow, hour)
                matching_patterns = self.pattern_by_dow_hour.get(key, [])
                if matching_patterns:
                    closest = min(matching_patterns,
                                  key=lambda p: abs(p['minute'] - minute))
                    schedule.append({
                        'replay_time': current_time,
                        'dow': dow,
                        'dow_name': current_time.strftime('%A'),
                        'hour': hour,
                        'minute': minute,
                        'queries_in_bucket': closest['queries_in_bucket'],
                        'bucket_duration_sec': closest['bucket_duration_sec'],
                        'source_datetime': closest['datetime'],
                        'source_dow_name': closest['dow_name']
                    })
                else:
                    schedule.append({
                        'replay_time': current_time,
                        'dow': dow,
                        'dow_name': current_time.strftime('%A'),
                        'hour': hour,
                        'minute': minute,
                        'queries_in_bucket': 0,
                        'bucket_duration_sec': bucket_duration,
                        'source_datetime': None,
                        'source_dow_name': None
                    })
            current_time += timedelta(seconds=bucket_duration)
        print(f"    - Generated {len(schedule)} time slots")
        print(f"\n[+] Schedule Preview (first 24 hours):")
        for i, slot in enumerate(schedule[:24]):
            if slot['queries_in_bucket'] > 0:
                print(f"    {slot['replay_time'].strftime('%a %H:%M')}: "
                      f"{slot['queries_in_bucket']:.1f} queries "
                      f"(from {slot['source_dow_name']} {slot['source_datetime'].strftime('%H:%M') if slot['source_datetime'] else 'N/A'})")
        return schedule

    def generate_dns_packet(self, src_ip, domain, dns_server='8.8.8.8'):
        query_id = random.randint(1, 65535)
        query_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME']
        weights = [0.70, 0.15, 0.05, 0.05, 0.05]
        qtype = random.choices(query_types, weights=weights)[0]
        dns_query = DNS(
            id=query_id,
            qr=0,
            opcode=0,
            rd=1,
            qd=DNSQR(qname=domain, qtype=qtype)
        )
        ip_layer = IP(src=src_ip, dst=dns_server)
        udp_layer = UDP(sport=random.randint(1024, 65535), dport=53)
        return ip_layer / udp_layer / dns_query

    def replay_schedule(self, schedule, speed_multiplier=1.0, dns_server='8.8.8.8', dry_run=False):
        if not schedule:
            print("[!] No schedule to replay")
            return
        print(f"\n[+] Starting Replay:")
        print(f"    - Speed: {speed_multiplier}x")
        print(f"    - DNS Server: {dns_server}")
        print(f"    - Total slots: {len(schedule)}")
        if dry_run:
            print("    - DRY RUN MODE")
        else:
            if not self.skip_dns_test:
                if not self.test_dns_server(dns_server):
                    print("[!] WARNING: DNS server did not respond. Continuing anyway (responses may fail).")
            else:
                print("[*] DNS server test skipped (--no-dns-test)")
        total_packets = 0
        start_time = time.time()
        for i, slot in enumerate(schedule):
            queries_in_bucket = slot['queries_in_bucket']
            bucket_duration = slot['bucket_duration_sec']
            num_queries_int = int(queries_in_bucket)
            fractional_part = queries_in_bucket - num_queries_int
            if fractional_part > 0 and random.random() < fractional_part:
                num_queries_int += 1
            num_queries = num_queries_int
            if num_queries > 0:
                print(f"[{i+1}/{len(schedule)}] {slot['replay_time'].strftime('%a %d %H:%M')}: "
                      f"sending {num_queries} queries "
                      f"(source: {slot['source_dow_name']} {slot['source_datetime'].strftime('%H:%M') if slot['source_datetime'] else 'N/A'})")
                query_interval = bucket_duration / num_queries / speed_multiplier
                for _ in range(num_queries):
                    src_ip = random.choice(self.source_ips)
                    domain = random.choice(self.domains)
                    if not dry_run:
                        try:
                            packet = self.generate_dns_packet(src_ip, domain, dns_server)
                            send(packet, verbose=False)
                            total_packets += 1
                        except Exception as e:
                            print(f"[!] Error: {e}")
                    else:
                        total_packets += 1
                    if query_interval > 0.001:
                        time.sleep(query_interval)
            if i < len(schedule) - 1:
                time_to_next = bucket_duration / speed_multiplier
                if time_to_next > 0:
                    time.sleep(time_to_next)
        elapsed = time.time() - start_time
        print(f"\n[+] Replay Complete!")
        print(f"    - Packets sent: {total_packets}")
        print(f"    - Elapsed time: {elapsed:.2f}s")
        print(f"    - Avg rate: {total_packets/elapsed:.2f} packets/sec")


def load_list_file(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[!] Error loading {filename}: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='DNS Traffic Replay with Day-of-Week Alignment (supports Blueprint files)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--blueprint', type=str,
                        help='Use a pre‑exported blueprint JSON file instead of querying Prometheus')
    parser.add_argument('--prometheus', default='http://localhost:9090',
                        help='Prometheus URL (ignored if --blueprint is used)')
    parser.add_argument('--instance', default='dnsdist:8083',
                        help='Instance filter (ignored if --blueprint is used)')
    parser.add_argument('--from', dest='start_time',
                        default='2026-01-08T05:00:00.000Z',
                        help='Historical data start time (ignored if --blueprint is used)')
    parser.add_argument('--to', dest='end_time',
                        default='2026-01-29T04:59:59.000Z',
                        help='Historical data end time (ignored if --blueprint is used)')
    parser.add_argument('--ips', required=True,
                        help='Source IPs file')
    parser.add_argument('--domains', required=True,
                        help='Domains file')
    parser.add_argument('--replay-start', dest='replay_start',
                        help='Replay start time (default: now) - format: YYYY-MM-DD HH:MM:SS')
    parser.add_argument('--replay-days', dest='replay_days', type=int, default=7,
                        help='Number of days to replay (default: 7)')
    parser.add_argument('--replay', action='store_true',
                        help='Actually send traffic')
    parser.add_argument('--speed', type=float, default=1.0,
                        help='Speed multiplier')
    parser.add_argument('--dns-server', default='8.8.8.8',
                        help='Target DNS server')
    parser.add_argument('--dry-run', action='store_true',
                        help='Dry run mode')
    parser.add_argument('--variance', type=float, default=0.15,
                        help='Traffic variance factor (blueprint mode only, default: 0.15)')
    parser.add_argument('--no-dns-test', action='store_true',
                        help='Skip DNS server responsiveness test (live replay only)')
    args = parser.parse_args()

    print("[+] Loading source IPs and domains...")
    source_ips = load_list_file(args.ips)
    domains = load_list_file(args.domains)
    print(f"[+] Loaded {len(source_ips)} IPs, {len(domains)} domains")

    if args.blueprint:
        replayer = DNSTrafficReplayerAligned(
            source_ips=source_ips,
            domains=domains,
            blueprint_file=args.blueprint
        )
    else:
        replayer = DNSTrafficReplayerAligned(
            prometheus_url=args.prometheus,
            start_time=args.start_time,
            end_time=args.end_time,
            source_ips=source_ips,
            domains=domains,
            instance_filter=args.instance
        )

    replayer.skip_dns_test = args.no_dns_test

    if not replayer.analyze_traffic_pattern():
        print("[!] Failed to analyze pattern")
        sys.exit(1)

    if args.replay_start:
        replay_start = datetime.strptime(args.replay_start, '%Y-%m-%d %H:%M:%S')
    else:
        replay_start = datetime.now()

    schedule = replayer.generate_replay_schedule(
        replay_start_time=replay_start,
        replay_duration_days=args.replay_days,
        variance_factor=args.variance if args.blueprint else 0.0
    )

    if not schedule:
        print("[!] Failed to generate schedule")
        sys.exit(1)

    if args.replay or args.dry_run:
        if args.replay and not args.dry_run:
            if os.geteuid() != 0:
                print("[!] Replay requires root. Use sudo.")
                sys.exit(1)
        replayer.replay_schedule(
            schedule=schedule,
            speed_multiplier=args.speed,
            dns_server=args.dns_server,
            dry_run=args.dry_run
        )
    else:
        print("\n[+] Schedule generated. Use --replay to send traffic.")


if __name__ == '__main__':
    main()
