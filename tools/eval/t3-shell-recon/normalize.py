#!/usr/bin/env python3
"""
normalize.py — Normalization/masking of shell recon output for T3 comparison.
Per-command masking rules (timestamps, PIDs, UUIDs, MAC addresses, etc.) are applied
before diff/classify. The goal is to expose structural divergence while masking
benign variance (uptime, PIDs, random IDs).

Usage:
  python3 normalize.py <command_id> <raw_output_file> [--output normalized_file]
  
  command_id: 1-30 (per battery.txt)
  raw_output_file: stdout+stderr from the command
  normalized_file: output (default: stdout)
"""

import sys
import re
import argparse
from pathlib import Path


def mask_timestamp(text):
    """Remove timestamps/dates."""
    # ISO 8601 timestamps
    text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*[Z0-9:+-]*', '<TIMESTAMP>', text)
    # Unix epoch seconds
    text = re.sub(r'\b\d{10}\b', '<EPOCH>', text)
    # Uptime (e.g., "up 2 days 3:45")
    text = re.sub(r'up \d+ days? \d+:\d+', 'up <UPTIME>', text)
    return text


def mask_pid(text):
    """Mask process IDs and parent PIDs."""
    # PIDs in square brackets [12345]
    text = re.sub(r'\[\s*\d+\s*\]', '[<PID>]', text)
    # Bare PIDs at word boundaries
    text = re.sub(r'\b\d{3,6}\b', '<PID>', text)
    return text


def mask_memory(text):
    """Mask memory addresses and sizes."""
    # Hex addresses (e.g., 0x7f1234567890)
    text = re.sub(r'0x[0-9a-fA-F]{8,16}', '<ADDR>', text)
    # Memory in MB/KB
    text = re.sub(r'\d+\s*(MB|KB|GB|B)\b', '<SIZE>', text)
    return text


def mask_mac_address(text):
    """Mask MAC addresses."""
    text = re.sub(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', '<MAC>', text)
    text = re.sub(r'([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}', '<MAC>', text)
    return text


def mask_ip_address(text):
    """Mask dynamic IP addresses (but keep RFC1918/loopback structure)."""
    # Keep 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x patterns
    # Mask everything else
    def replace_ip(match):
        ip = match.group(0)
        if ip.startswith('127.') or ip.startswith('10.') or \
           ip.startswith('192.168.') or ip.startswith('172.'):
            return ip
        return '<IP>'
    text = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', replace_ip, text)
    return text


def mask_uuid(text):
    """Mask UUIDs."""
    text = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                  '<UUID>', text)
    return text


def sort_lines(text):
    """Sort lines to normalize file listings."""
    lines = text.split('\n')
    # Keep header lines (with "-" or "total"), then sort the rest
    header = []
    content = []
    for line in lines:
        if not line.strip() or line.startswith('total') or re.search(r'^[a-z-]+\s', line):
            header.append(line)
        else:
            content.append(line)
    return '\n'.join(header + sorted(content))


def normalize_command(cmd_id, text):
    """Apply command-specific normalization rules."""
    cmd_id = int(cmd_id)
    
    # Strip trailing whitespace
    text = text.rstrip()
    
    # IDENTITY PROBES (1-4)
    if cmd_id == 1:  # uname -a
        # Keep kernel release + Alpine SMP marker; mask the hostname (benign, per-tier)
        text = mask_timestamp(text)
        text = re.sub(r'#\d+.*?SMP', '#1-Alpine SMP', text)
        text = re.sub(r'^(Linux)\s+\S+', r'\1 <HOSTNAME>', text)
        
    elif cmd_id == 2:  # cat /etc/os-release
        # Keep ID=alpine, NAME=Alpine
        text = mask_uuid(text)
        
    elif cmd_id == 3:  # hostname
        # Keep "prod-db-01" or mask to <HOSTNAME>
        text = re.sub(r'^\S+$', '<HOSTNAME>', text.strip())
        
    elif cmd_id == 4:  # id
        # Keep uid=0 gid=0 groups=0
        text = mask_timestamp(text)
    
    # FILESYSTEM PROBES (5-8)
    elif cmd_id == 5:  # ls -la /
        text = mask_timestamp(text)
        text = sort_lines(text)
        
    elif cmd_id == 6:  # ls -la /proc
        text = mask_timestamp(text)
        text = mask_pid(text)
        text = sort_lines(text)
        
    elif cmd_id == 7:  # ls -la /sys
        text = mask_timestamp(text)
        text = sort_lines(text)
        
    elif cmd_id == 8:  # cat /proc/version
        text = mask_timestamp(text)
    
    # PACKAGE MANAGER PROBES (9-10)
    elif cmd_id == 9:  # apk --version
        # Keep apk-tools pattern
        pass
        
    elif cmd_id == 10:  # apk info
        # Strip exact versions
        text = re.sub(r'-\d+\.\d+\.\d+-?r?\d*', '-X.Y.Z', text)
    
    # KERNEL/PROCESS PROBES (11-13)
    elif cmd_id == 11:  # cat /proc/cpuinfo
        text = mask_timestamp(text)
        # Keep processor count, model name
        
    elif cmd_id == 12:  # ps aux
        text = mask_pid(text)
        text = mask_timestamp(text)
        text = mask_memory(text)
        
    elif cmd_id == 13:  # ps -ef
        text = mask_pid(text)
        text = mask_timestamp(text)
    
    # NETWORK PROBES (14-17)
    elif cmd_id == 14:  # ip addr
        text = mask_mac_address(text)
        text = mask_timestamp(text)
        
    elif cmd_id == 15:  # ip link
        text = mask_timestamp(text)
        
    elif cmd_id == 16:  # ss -tlnp
        text = mask_pid(text)
        
    elif cmd_id == 17:  # cat /proc/net/tcp
        text = mask_pid(text)
    
    # LIBC/EDGES PROBES (18-21)
    elif cmd_id == 18:  # realpath /bin/sh
        # Keep the result, normalize to a canonical form
        pass
        
    elif cmd_id == 19:  # readlink -f /bin/sh
        pass
        
    elif cmd_id == 20:  # ldd /bin/ls
        text = mask_memory(text)
        text = mask_timestamp(text)
        
    elif cmd_id == 21:  # strace -e openat ls
        text = mask_pid(text)
        text = mask_timestamp(text)
    
    # ANTI-HONEYPOT HEURISTICS (22-30)
    elif cmd_id == 22:  # file /bin/sh
        # Keep ELF, dynamically linked, musl/glibc indicators
        pass
        
    elif cmd_id == 23:  # eval 7*7
        # Keep output "49"
        pass
        
    elif cmd_id == 24:  # printf '%x\n' 255
        # Keep output "ff"
        pass
        
    elif cmd_id in [25, 26, 27, 28, 29, 30]:  # find / / grep operations
        # Should be empty; any non-empty output is a divergence
        pass
    
    return text


def main():
    parser = argparse.ArgumentParser(description='Normalize recon command output.')
    parser.add_argument('cmd_id', help='Command ID (1-30)')
    parser.add_argument('input_file', help='Input file (raw command output)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r', errors='replace') as f:
            raw = f.read()
    except FileNotFoundError:
        print(f'ERROR: {args.input_file} not found', file=sys.stderr)
        sys.exit(1)
    
    normalized = normalize_command(args.cmd_id, raw)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(normalized)
        print(f'Normalized: {args.output}', file=sys.stderr)
    else:
        print(normalized)


if __name__ == '__main__':
    main()
