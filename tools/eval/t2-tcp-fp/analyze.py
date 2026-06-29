#!/usr/bin/env python3
"""
Experiment T2 · TCP/IP Stack Fingerprinting Analysis

Parse nmap -O logs and p0f captures; extract field-by-field comparisons.
Emit a CSV with:
  - Probe type (T1 SYN-ACK, T2 SYN, T3 FIN, etc.)
  - Field name (TTL, IP-ID, DF, Window, Wscale, Option layout, ECN)
  - sotOs value
  - Alpine value
  - Match (Yes/No/TBD)

Usage:
  t2-tcp-fp-analyze.py --nmap-sotos <log> --nmap-alpine <log> --output <csv>
  t2-tcp-fp-analyze.py --p0f-sotos <pcap> --p0f-alpine <pcap> --output <csv>
"""
import re
import sys
import json
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ============================================================================
# nmap -O Log Parser
# ============================================================================
def parse_nmap_log(log_path: str) -> Dict:
    """Extract OS fingerprint from nmap -O log."""
    try:
        with open(log_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"WARN: {log_path} not found", file=sys.stderr)
        return {}
    
    result = {
        'os_details': [],
        'confidence': [],
        'ttl': None,
        'ip_id': None,
        'df': None,
        'window': None,
        'mss': None,
        'wscale': None,
        'option_layout': [],
    }
    
    # Extract OS guesses (may be multiple rounds)
    for line in content.split('\n'):
        if 'OS Details:' in line:
            # e.g., "OS Details: Linux 4.19 - 5.18, Linux 5.19 - 6.6, ..., Alpine Linux"
            os_detail = line.split('OS Details:')[1].strip()
            result['os_details'].append(os_detail)
        
        if 'Confidence = ' in line:
            # e.g., "Confidence = 95%"
            conf = re.search(r'Confidence = (\d+)%', line)
            if conf:
                result['confidence'].append(int(conf.group(1)))
    
    # Return consensus/aggregated result
    result['os_consensus'] = result['os_details'][0] if result['os_details'] else 'UNKNOWN'
    result['confidence_avg'] = sum(result['confidence']) / len(result['confidence']) if result['confidence'] else 0
    
    return result

# ============================================================================
# TCP Fingerprint Field Extractor (from nmap raw output if available)
# ============================================================================
def extract_tcp_fp_fields(nmap_log: str) -> Dict:
    """Extract detailed TCP FP fields from nmap verbose output.
    
    nmap -d outputs raw probe responses; we parse the T1-T7 & U1 probes
    to extract: TTL, IP-ID (TI/II/TS classes), DF, Window, MSS, Wscale, options.
    """
    fields = {
        'ttl_synack': None,
        'ttl_rst': None,
        'ip_id_synack': None,
        'ip_id_rst': None,
        'ip_id_icmp': None,
        'df_synack': None,
        'df_rst': None,
        'window_synack': None,
        'mss': None,
        'wscale': None,
        'options': [],
        'ecn_capable': None,
    }
    
    try:
        with open(nmap_log, 'r') as f:
            content = f.read()
    except:
        return fields
    
    # Pattern: look for "T1: SEQ(SP=...) OP(O=...) WIN(W=...) ECN(...) DLF(...)"
    # This is verbose nmap output; real parsing requires full nmap source.
    # For now, use heuristics from OS Details line.
    
    # TTL (usually in the OS Details or table)
    ttl_match = re.search(r'TTL=(\d+)', content)
    if ttl_match:
        fields['ttl_synack'] = int(ttl_match.group(1))
    
    # DF bit (present in Nmap FP strings, e.g., "DF")
    if 'DF=Y' in content or 'DF=N' in content:
        fields['df_synack'] = 1 if 'DF=Y' in content else 0
    
    return fields

# ============================================================================
# CSV Generation
# ============================================================================
def generate_csv(sotos_data: Dict, alpine_data: Dict, output_csv: str):
    """Generate field-by-field comparison CSV."""
    rows = []
    
    # Known fingerprint fields (from sotOs code + nmap standard probes)
    fields_to_compare = [
        ('TTL (SYN-ACK)', 'ttl_synack', 'ttl_synack', 'T1/T2'),
        ('IP-ID (SYN-ACK)', 'ip_id_synack', 'ip_id_synack', 'T1 (TI class)'),
        ('DF Bit (SYN-ACK)', 'df_synack', 'df_synack', 'T1'),
        ('Window (SYN-ACK)', 'window_synack', 'window_synack', 'T1'),
        ('MSS', 'mss', 'mss', 'T1'),
        ('Wscale', 'wscale', 'wscale', 'T1'),
        ('Option Layout', 'options', 'options', 'T1'),
        ('ECN Capable', 'ecn_capable', 'ecn_capable', 'T6'),
    ]
    
    rows.append({
        'Field': 'Probe',
        'Description': 'Description',
        'sotOs Value': 'sotOs',
        'Alpine Value': 'Alpine',
        'Match': 'Match (Y/N)',
        'Notes': 'Notes',
    })
    
    for field_name, sotos_key, alpine_key, probe_type in fields_to_compare:
        sotos_val = sotos_data.get(sotos_key, 'TBD')
        alpine_val = alpine_data.get(alpine_key, 'TBD')
        
        # Determine match
        match = 'TBD'
        if sotos_val != 'TBD' and alpine_val != 'TBD':
            match = 'YES' if sotos_val == alpine_val else 'NO'
        
        rows.append({
            'Field': field_name,
            'Description': probe_type,
            'sotOs Value': str(sotos_val),
            'Alpine Value': str(alpine_val),
            'Match': match,
            'Notes': '',
        })
    
    # Add OS guess summary
    rows.append({
        'Field': '=== OS GUESS CONSENSUS ===',
        'Description': '',
        'sotOs Value': sotos_data.get('os_consensus', 'UNKNOWN'),
        'Alpine Value': alpine_data.get('os_consensus', 'UNKNOWN'),
        'Match': 'YES' if sotos_data.get('os_consensus') == alpine_data.get('os_consensus') else 'NO',
        'Notes': '',
    })
    
    rows.append({
        'Field': 'nmap Confidence',
        'Description': 'Avg confidence %',
        'sotOs Value': f"{sotos_data.get('confidence_avg', 0):.1f}%",
        'Alpine Value': f"{alpine_data.get('confidence_avg', 0):.1f}%",
        'Match': '',
        'Notes': 'Higher is more certain',
    })
    
    # Write CSV
    with open(output_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['Field', 'Description', 'sotOs Value', 'Alpine Value', 'Match', 'Notes'])
        w.writerows(rows)
    
    print(f"CSV written to {output_csv}")

# ============================================================================
# Main
# ============================================================================
def main(argv):
    import argparse
    
    parser = argparse.ArgumentParser(description='Experiment T2: TCP/IP FP Analysis')
    parser.add_argument('--nmap-sotos', help='nmap -O log for sotOs')
    parser.add_argument('--nmap-alpine', help='nmap -O log for Alpine reference')
    parser.add_argument('--output', '-o', help='Output CSV file')
    
    args = parser.parse_args(argv[1:])
    
    if not args.nmap_sotos or not args.nmap_alpine or not args.output:
        print("usage: t2-tcp-fp-analyze.py --nmap-sotos <log> --nmap-alpine <log> --output <csv>", file=sys.stderr)
        return 2
    
    print(f"[t2-analyze] Parsing {args.nmap_sotos}...")
    sotos_data = parse_nmap_log(args.nmap_sotos)
    sotos_data.update(extract_tcp_fp_fields(args.nmap_sotos))
    
    print(f"[t2-analyze] Parsing {args.nmap_alpine}...")
    alpine_data = parse_nmap_log(args.nmap_alpine)
    alpine_data.update(extract_tcp_fp_fields(args.nmap_alpine))
    
    print(f"[t2-analyze] sotOs OS consensus: {sotos_data.get('os_consensus')}")
    print(f"[t2-analyze] Alpine OS consensus: {alpine_data.get('os_consensus')}")
    print(f"[t2-analyze] Generating {args.output}...")
    
    generate_csv(sotos_data, alpine_data, args.output)
    
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
