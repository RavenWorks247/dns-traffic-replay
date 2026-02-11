#!/usr/bin/env python3
"""
DNS Traffic Pattern Blueprint System
Export patterns from Prometheus to portable JSON blueprints
Replay anywhere without needing Prometheus access
"""

import requests
import json
import time
import random
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import IP, UDP, DNS, DNSQR, send
import argparse
import sys
import os

class TrafficPatternBlueprint:
    """Manages traffic pattern blueprints - export and import"""
    
    @staticmethod
    def export_from_prometheus(prometheus_url, start_time, end_time, instance_filter, 
                              time_offset_hours=0, output_file='traffic_blueprint.json',
                              step_minutes=1):
        """Export traffic pattern from Prometheus to a blueprint file"""
        print("[+] Exporting Traffic Pattern Blueprint from Prometheus")
        print(f"[+] Time offset: {time_offset_hours:+d} hours")
        print(f"[+] Step size: {step_minutes} minute(s)")
        
        # Test connection
        try:
            response = requests.get(f"{prometheus_url}/api/v1/query", 
                                   params={'query': 'up'}, timeout=5)
            response.raise_for_status()
            print(f"[+] Prometheus connection OK: {prometheus_url}")
        except Exception as e:
            print(f"[!] Cannot connect to Prometheus: {e}")
            return False
        
        # Parse timestamps
        start_ts = datetime.fromisoformat(start_time.replace('Z', '+00:00')).timestamp()
        end_ts = datetime.fromisoformat(end_time.replace('Z', '+00:00')).timestamp()
        
        duration = end_ts - start_ts
        step = f'{step_minutes}m' if step_minutes > 1 else '60s'
        step_seconds = step_minutes * 60
        
        print(f"[+] Querying: {start_time} to {end_time}")
        print(f"[+] Duration: {duration / 86400:.1f} days")
        if step_minutes == 1:
            print(f"[+] Resolution: 1-minute (high detail)")
        elif step_minutes <= 5:
            print(f"[+] Resolution: {step_minutes}-minute (medium detail)")
        else:
            print(f"[+] Resolution: {step_minutes}-minute (coarse detail)")
        
        # Calculate number of expected points
        expected_points = int(duration / step_seconds)
        max_points_per_query = 10000  # Prometheus limit is typically 11,000
        
        # Determine if we need to chunk the query
        if expected_points > max_points_per_query:
            chunk_duration = max_points_per_query * step_seconds
            num_chunks = int(np.ceil(duration / chunk_duration))
            print(f"[+] Large time range detected: {expected_points} points")
            print(f"[+] Splitting into {num_chunks} chunks to stay within Prometheus limits")
        else:
            num_chunks = 1
            chunk_duration = duration
        
        # Query Prometheus in chunks
        url = f"{prometheus_url}/api/v1/query_range"
        pattern_by_slot = defaultdict(list)  # (dow, hour, minute) -> [qps values]
        raw_data = []
        
        for chunk_idx in range(num_chunks):
            chunk_start = start_ts + (chunk_idx * chunk_duration)
            chunk_end = min(start_ts + ((chunk_idx + 1) * chunk_duration), end_ts)
            
            if num_chunks > 1:
                chunk_start_dt = datetime.fromtimestamp(chunk_start).strftime('%Y-%m-%d %H:%M')
                chunk_end_dt = datetime.fromtimestamp(chunk_end).strftime('%Y-%m-%d %H:%M')
                print(f"[+] Chunk {chunk_idx + 1}/{num_chunks}: {chunk_start_dt} to {chunk_end_dt}")
            
            queries_query = f'sum(rate(dnsdist_queries{{instance=~"{instance_filter}"}}[5m]))'
            
            params = {
                'query': queries_query,
                'start': chunk_start,
                'end': chunk_end,
                'step': step
            }
            
            try:
                response = requests.get(url, params=params, timeout=30)
                if response.status_code != 200:
                    # Try without instance filter
                    if chunk_idx == 0:  # Only print once
                        print("[+] Trying without instance filter...")
                    params['query'] = 'sum(rate(dnsdist_queries[5m]))'
                    response = requests.get(url, params=params, timeout=30)
                
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                print(f"[!] Query error for chunk {chunk_idx + 1}: {e}")
                return False
            
            if data.get('status') != 'success':
                print(f"[!] Query failed for chunk {chunk_idx + 1}: {data}")
                return False
            
            results = data.get('data', {}).get('result', [])
            if not results:
                print(f"[!] No data returned for chunk {chunk_idx + 1}")
                continue
            
            # Process this chunk
            for series in results:
                values = series.get('values', [])
                
                for timestamp, value in values:
                    try:
                        rate_per_sec = float(value)
                        
                        # Apply time offset
                        dt_original = datetime.fromtimestamp(float(timestamp))
                        dt = dt_original + timedelta(hours=time_offset_hours)
                        
                        dow = dt.weekday()
                        hour = dt.hour
                        minute = dt.minute
                        
                        slot_key = (dow, hour, minute)
                        pattern_by_slot[slot_key].append(rate_per_sec)
                        
                        raw_data.append({
                            'timestamp': float(timestamp) + (time_offset_hours * 3600),
                            'dow': dow,
                            'hour': hour,
                            'minute': minute,
                            'qps': rate_per_sec
                        })
                        
                    except (ValueError, TypeError):
                        continue
            
            if num_chunks > 1:
                print(f"    - Processed {len([v for s in results for v in s.get('values', [])])} points from this chunk")
        
        if not pattern_by_slot:
            print("[!] No valid data points")
            return False
        
        print(f"[+] Collected {len(raw_data)} data points")
        print(f"[+] Unique time slots: {len(pattern_by_slot)}")
        
        # Calculate statistics for each slot
        blueprint = {
            'metadata': {
                'created': datetime.now().isoformat(),
                'source_prometheus': prometheus_url,
                'source_start': start_time,
                'source_end': end_time,
                'time_offset_hours': time_offset_hours,
                'duration_days': duration / 86400,
                'total_samples': len(raw_data),
                'resolution_seconds': step_seconds,
                'step_minutes': step_minutes
            },
            'patterns': {}
        }
        
        for (dow, hour, minute), qps_values in pattern_by_slot.items():
            # Round minute to step boundary for cleaner keys
            minute_rounded = (minute // step_minutes) * step_minutes
            slot_key = f"{dow}:{hour:02d}:{minute_rounded:02d}"
            
            # If this key already exists (due to rounding), merge the data
            if slot_key in blueprint['patterns']:
                existing = blueprint['patterns'][slot_key]
                all_values = list(qps_values) + [existing['qps_mean']] * existing['samples']
                blueprint['patterns'][slot_key] = {
                    'dow': dow,
                    'hour': hour,
                    'minute': minute_rounded,
                    'samples': len(all_values),
                    'qps_mean': float(np.mean(all_values)),
                    'qps_std': float(np.std(all_values)),
                    'qps_min': float(np.min(all_values)),
                    'qps_max': float(np.max(all_values)),
                    'qps_p50': float(np.percentile(all_values, 50)),
                    'qps_p95': float(np.percentile(all_values, 95))
                }
            else:
                blueprint['patterns'][slot_key] = {
                    'dow': dow,
                    'hour': hour,
                    'minute': minute_rounded,
                    'samples': len(qps_values),
                    'qps_mean': float(np.mean(qps_values)),
                    'qps_std': float(np.std(qps_values)),
                    'qps_min': float(np.min(qps_values)),
                    'qps_max': float(np.max(qps_values)),
                    'qps_p50': float(np.percentile(qps_values, 50)),
                    'qps_p95': float(np.percentile(qps_values, 95))
                }
        
        # Add summary statistics
        all_qps = [v for values in pattern_by_slot.values() for v in values]
        blueprint['summary'] = {
            'avg_qps': float(np.mean(all_qps)),
            'std_qps': float(np.std(all_qps)),
            'min_qps': float(np.min(all_qps)),
            'max_qps': float(np.max(all_qps)),
            'p50_qps': float(np.percentile(all_qps, 50)),
            'p95_qps': float(np.percentile(all_qps, 95)),
            'total_slots': len(pattern_by_slot)
        }
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(blueprint, f, indent=2)
        
        print(f"\n[+] Blueprint exported successfully!")
        print(f"[+] Output file: {output_file}")
        print(f"[+] File size: {os.path.getsize(output_file) / 1024:.1f} KB")
        
        # Print summary
        print(f"\n[+] Blueprint Summary:")
        print(f"    - Time slots captured: {len(pattern_by_slot)}")
        print(f"    - Average QPS: {blueprint['summary']['avg_qps']:.2f}")
        print(f"    - QPS range: {blueprint['summary']['min_qps']:.2f} - {blueprint['summary']['max_qps']:.2f}")
        print(f"    - 95th percentile: {blueprint['summary']['p95_qps']:.2f}")
        
        # Show busiest slots
        sorted_patterns = sorted(blueprint['patterns'].items(), 
                                key=lambda x: x[1]['qps_mean'], reverse=True)
        
        print(f"\n[+] Busiest Time Slots:")
        dow_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        for slot_key, data in sorted_patterns[:10]:
            dow_name = dow_names[data['dow']]
            print(f"    - {dow_name} {data['hour']:02d}:{data['minute']:02d} - "
                  f"{data['qps_mean']:.2f} qps (±{data['qps_std']:.2f})")
        
        return True
    
    @staticmethod
    def load_blueprint(blueprint_file):
        """Load a traffic pattern blueprint from file"""
        try:
            with open(blueprint_file, 'r') as f:
                blueprint = json.load(f)
            
            print(f"[+] Loaded blueprint: {blueprint_file}")
            print(f"[+] Created: {blueprint['metadata']['created']}")
            print(f"[+] Source duration: {blueprint['metadata']['duration_days']:.1f} days")
            print(f"[+] Total samples: {blueprint['metadata']['total_samples']}")
            print(f"[+] Unique time slots: {blueprint['summary']['total_slots']}")
            
            return blueprint
        except Exception as e:
            print(f"[!] Error loading blueprint: {e}")
            return None


class BlueprintReplayer:
    """Replays traffic from a blueprint file"""
    
    def __init__(self, blueprint, source_ips, domains):
        self.blueprint = blueprint
        self.source_ips = source_ips
        self.domains = domains
        self.patterns = blueprint['patterns']
        
    def generate_schedule(self, replay_start_time=None, replay_duration_days=7, 
                         variance_factor=0.15):
        """Generate replay schedule from blueprint"""
        if replay_start_time is None:
            replay_start_time = datetime.now()
        
        print(f"\n[+] Generating Replay Schedule from Blueprint:")
        print(f"    - Replay start: {replay_start_time.strftime('%Y-%m-%d %H:%M:%S %A')}")
        print(f"    - Duration: {replay_duration_days} days")
        print(f"    - Variance factor: ±{variance_factor*100:.0f}%")
        print(f"    - Available patterns: {len(self.patterns)}")
        
        schedule = []
        current_time = replay_start_time
        end_time = replay_start_time + timedelta(days=replay_duration_days)
        
        bucket_duration = 60  # 1-minute buckets
        
        while current_time < end_time:
            dow = current_time.weekday()
            hour = current_time.hour
            minute = current_time.minute
            
            # Look up pattern for this exact time slot
            slot_key = f"{dow}:{hour:02d}:{minute:02d}"
            pattern = self.patterns.get(slot_key)
            
            if pattern:
                # Use mean with realistic variance
                base_qps = pattern['qps_mean']
                queries_in_bucket = base_qps * bucket_duration
                
                # Add variance based on historical std dev
                if pattern['samples'] > 1 and pattern['qps_std'] > 0:
                    variance = np.random.normal(0, pattern['qps_std'] * bucket_duration)
                else:
                    variance = np.random.normal(0, queries_in_bucket * variance_factor)
                
                queries_in_bucket = max(0, queries_in_bucket + variance)
                
                # Occasional spikes (5% chance)
                if random.random() < 0.05:
                    spike_factor = random.uniform(1.2, 2.0)
                    queries_in_bucket *= spike_factor
                
                source_info = f"{pattern['samples']} samples, μ={pattern['qps_mean']:.2f}"
            else:
                # No pattern for this slot - minimal traffic
                queries_in_bucket = 0
                source_info = "no data"
            
            schedule.append({
                'replay_time': current_time,
                'dow': dow,
                'dow_name': current_time.strftime('%A'),
                'hour': hour,
                'minute': minute,
                'queries_in_bucket': queries_in_bucket,
                'bucket_duration_sec': bucket_duration,
                'source_info': source_info
            })
            
            current_time += timedelta(seconds=bucket_duration)
        
        print(f"    - Generated {len(schedule)} time slots")
        
        # Show preview
        self._print_schedule_preview(schedule)
        
        return schedule
    
    def _print_schedule_preview(self, schedule):
        """Print schedule preview"""
        print(f"\n[+] Schedule Preview (first 3 hours):")
        preview_slots = [s for s in schedule[:180] if s['queries_in_bucket'] > 0.5][:20]
        
        for slot in preview_slots:
            print(f"    {slot['replay_time'].strftime('%a %H:%M')}: "
                  f"{slot['queries_in_bucket']:6.1f} queries "
                  f"({slot['source_info']})")
        
        # Show statistics
        total_queries = sum(s['queries_in_bucket'] for s in schedule)
        avg_qps = total_queries / (len(schedule) * 60)
        
        print(f"\n[+] Schedule Statistics:")
        print(f"    - Total queries planned: {total_queries:,.0f}")
        print(f"    - Average QPS: {avg_qps:.2f}")
        print(f"    - Active slots: {sum(1 for s in schedule if s['queries_in_bucket'] > 0)}")
    
    def generate_dns_packet(self, src_ip, domain, dns_server='8.8.8.8'):
        """Generate a realistic DNS query packet"""
        query_id = random.randint(1, 65535)
        
        # Realistic query type distribution
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
        packet = ip_layer / udp_layer / dns_query
        
        return packet
    
    def replay(self, schedule, speed_multiplier=1.0, dns_server='8.8.8.8', 
              dry_run=False, smooth_traffic=True):
        """Replay traffic from schedule"""
        if not schedule:
            print("[!] No schedule to replay")
            return
        
        print(f"\n[+] Starting Blueprint Replay:")
        print(f"    - Speed: {speed_multiplier}x")
        print(f"    - DNS Server: {dns_server}")
        print(f"    - Total slots: {len(schedule)}")
        print(f"    - Traffic smoothing: {'enabled' if smooth_traffic else 'disabled'}")
        
        if dry_run:
            print("    - DRY RUN MODE")
        
        total_packets = 0
        start_time = time.time()
        last_status = start_time
        
        for i, slot in enumerate(schedule):
            queries_in_bucket = slot['queries_in_bucket']
            bucket_duration = slot['bucket_duration_sec']
            
            # Handle fractional queries
            num_queries_int = int(queries_in_bucket)
            fractional_part = queries_in_bucket - num_queries_int
            if fractional_part > 0 and random.random() < fractional_part:
                num_queries_int += 1
            
            num_queries = num_queries_int
            
            if num_queries > 0:
                # Calculate inter-query interval
                if smooth_traffic and num_queries > 1:
                    query_interval = bucket_duration / num_queries / speed_multiplier
                else:
                    query_interval = 0.001
                
                # Send queries
                for q in range(num_queries):
                    src_ip = random.choice(self.source_ips)
                    domain = random.choice(self.domains)
                    
                    if not dry_run:
                        try:
                            packet = self.generate_dns_packet(src_ip, domain, dns_server)
                            send(packet, verbose=False)
                            total_packets += 1
                        except Exception as e:
                            if total_packets == 0:
                                print(f"[!] Error sending packet: {e}")
                    else:
                        total_packets += 1
                    
                    if query_interval > 0.001:
                        time.sleep(query_interval)
            
            # Status update every 5 minutes
            current = time.time()
            if current - last_status >= 300:
                elapsed = current - start_time
                rate = total_packets / elapsed if elapsed > 0 else 0
                progress = (i + 1) / len(schedule) * 100
                print(f"[{progress:5.1f}%] {slot['replay_time'].strftime('%a %d %H:%M')} - "
                      f"{total_packets:,} packets sent, {rate:.1f} pkt/s avg")
                last_status = current
            
            # Sleep until next bucket
            if i < len(schedule) - 1:
                time_to_next = bucket_duration / speed_multiplier
                time_spent = time.time() - current
                sleep_time = max(0, time_to_next - time_spent)
                if sleep_time > 0:
                    time.sleep(sleep_time)
        
        elapsed = time.time() - start_time
        print(f"\n[+] Replay Complete!")
        print(f"    - Packets sent: {total_packets:,}")
        print(f"    - Elapsed time: {elapsed:.2f}s ({elapsed/3600:.2f} hours)")
        print(f"    - Avg rate: {total_packets/elapsed:.2f} packets/sec")


def load_list_file(filename):
    """Load a list from a file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[!] Error loading {filename}: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='DNS Traffic Blueprint System - Export and Replay',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WORKFLOW:
  1. Export blueprint from Prometheus (requires --export):
     python3 %(prog)s --export --prometheus http://localhost:9090 \\
       --from 2026-01-08T05:00:00.000Z --to 2026-01-29T04:59:59.000Z \\
       --time-offset 10 --output my_pattern.json

  2. Replay from blueprint anywhere (no Prometheus needed):
     python3 %(prog)s --blueprint my_pattern.json \\
       --ips ips.txt --domains domains.txt --replay --dry-run

EXAMPLES:
  # Export pattern with clock correction
  python3 %(prog)s --export --time-offset 10 --output office_pattern.json

  # Replay at 10x speed for testing
  python3 %(prog)s --blueprint office_pattern.json \\
    --ips ips.txt --domains domains.txt --replay --speed 10 --dry-run

  # Production replay
  sudo python3 %(prog)s --blueprint office_pattern.json \\
    --ips ips.txt --domains domains.txt --replay \\
    --dns-server 192.168.1.100 --replay-days 14
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--export', action='store_true',
                           help='Export mode: create blueprint from Prometheus')
    mode_group.add_argument('--blueprint', type=str,
                           help='Replay mode: use existing blueprint file')
    
    # Export mode arguments
    export_group = parser.add_argument_group('Export Options')
    export_group.add_argument('--prometheus', default='http://localhost:9090',
                             help='Prometheus URL (export mode)')
    export_group.add_argument('--instance', default='dnsdist:8083',
                             help='Instance filter (export mode)')
    export_group.add_argument('--from', dest='start_time',
                             default='2026-01-08T05:00:00.000Z',
                             help='Historical data start time (export mode)')
    export_group.add_argument('--to', dest='end_time',
                             default='2026-01-29T04:59:59.000Z',
                             help='Historical data end time (export mode)')
    export_group.add_argument('--time-offset', type=int, default=0,
                             help='Time offset in hours to correct clock skew')
    export_group.add_argument('--output', default='traffic_blueprint.json',
                             help='Output blueprint file (export mode)')
    export_group.add_argument('--step', type=int, default=1,
                             help='Step size in minutes (1=high detail, 5=medium, 15=coarse, default: 1)')
    
    # Replay mode arguments
    replay_group = parser.add_argument_group('Replay Options')
    replay_group.add_argument('--ips',
                             help='Source IPs file (replay mode, required)')
    replay_group.add_argument('--domains',
                             help='Domains file (replay mode, required)')
    replay_group.add_argument('--replay-start',
                             help='Replay start time (default: now) - format: YYYY-MM-DD HH:MM:SS')
    replay_group.add_argument('--replay-days', type=int, default=7,
                             help='Number of days to replay (default: 7)')
    replay_group.add_argument('--replay', action='store_true',
                             help='Actually send traffic')
    replay_group.add_argument('--speed', type=float, default=1.0,
                             help='Speed multiplier (default: 1.0)')
    replay_group.add_argument('--variance', type=float, default=0.15,
                             help='Traffic variance factor (default: 0.15)')
    replay_group.add_argument('--dns-server', default='8.8.8.8',
                             help='Target DNS server')
    replay_group.add_argument('--dry-run', action='store_true',
                             help='Dry run mode')
    replay_group.add_argument('--no-smooth', action='store_true',
                             help='Disable traffic smoothing')
    
    args = parser.parse_args()
    
    # EXPORT MODE
    if args.export:
        success = TrafficPatternBlueprint.export_from_prometheus(
            prometheus_url=args.prometheus,
            start_time=args.start_time,
            end_time=args.end_time,
            instance_filter=args.instance,
            time_offset_hours=args.time_offset,
            output_file=args.output,
            step_minutes=args.step
        )
        
        if success:
            print(f"\n[+] Blueprint ready for replay!")
            print(f"[+] Share '{args.output}' to replay anywhere without Prometheus")
            sys.exit(0)
        else:
            print("[!] Export failed")
            sys.exit(1)
    
    # REPLAY MODE
    elif args.blueprint:
        # Validate required arguments
        if not args.ips or not args.domains:
            print("[!] Replay mode requires --ips and --domains")
            sys.exit(1)
        
        # Load blueprint
        blueprint = TrafficPatternBlueprint.load_blueprint(args.blueprint)
        if not blueprint:
            sys.exit(1)
        
        # Load IPs and domains
        print("\n[+] Loading source IPs and domains...")
        source_ips = load_list_file(args.ips)
        domains = load_list_file(args.domains)
        print(f"[+] Loaded {len(source_ips)} IPs, {len(domains)} domains")
        
        # Create replayer
        replayer = BlueprintReplayer(blueprint, source_ips, domains)
        
        # Parse replay start time
        if args.replay_start:
            replay_start = datetime.strptime(args.replay_start, '%Y-%m-%d %H:%M:%S')
        else:
            replay_start = datetime.now()
        
        # Generate schedule
        schedule = replayer.generate_schedule(
            replay_start_time=replay_start,
            replay_duration_days=args.replay_days,
            variance_factor=args.variance
        )
        
        if not schedule:
            print("[!] Failed to generate schedule")
            sys.exit(1)
        
        # Replay if requested
        if args.replay or args.dry_run:
            if args.replay and not args.dry_run:
                import os
                if os.geteuid() != 0:
                    print("[!] Replay requires root. Use sudo.")
                    sys.exit(1)
            
            replayer.replay(
                schedule=schedule,
                speed_multiplier=args.speed,
                dns_server=args.dns_server,
                dry_run=args.dry_run,
                smooth_traffic=not args.no_smooth
            )
        else:
            print("\n[+] Schedule generated. Use --replay to send traffic.")


if __name__ == '__main__':
    main()
