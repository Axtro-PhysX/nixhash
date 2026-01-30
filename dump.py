#!/usr/bin/env python3
"""
Shadow/Passwd Hash Extractor for John the Ripper
-------------------------------------------------
This script combines /etc/passwd and /etc/shadow files to create
a format suitable for password cracking with John the Ripper.

Requirements: Must be run as root (or with sudo) to read /etc/shadow
"""

import os
import sys
import argparse
import re
from datetime import datetime
from pathlib import Path


def check_root():
    """Check if script is running with root privileges."""
    if os.geteuid() != 0:
        print("[!] Warning: This script requires root privileges to read /etc/shadow")
        print("[!] Please run with: sudo python3 shadow_extractor.py")
        sys.exit(1)


def parse_passwd(passwd_file="/etc/passwd"):
    """
    Parse /etc/passwd and return a dictionary of users.
    
    Returns:
        dict: {username: {'uid': uid, 'gid': gid, 'gecos': gecos, 'home': home, 'shell': shell}}
    """
    users = {}
    
    try:
        with open(passwd_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                if len(parts) >= 7:
                    username = parts[0]
                    # parts[1] is usually 'x' indicating shadow passwords
                    uid = parts[2]
                    gid = parts[3]
                    gecos = parts[4]  # GECOS field (full name, etc.)
                    home = parts[5]
                    shell = parts[6]
                    
                    users[username] = {
                        'uid': uid,
                        'gid': gid,
                        'gecos': gecos,
                        'home': home,
                        'shell': shell
                    }
    except FileNotFoundError:
        print(f"[!] Error: {passwd_file} not found")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Error: Permission denied reading {passwd_file}")
        sys.exit(1)
    
    return users


def parse_shadow(shadow_file="/etc/shadow"):
    """
    Parse /etc/shadow and return a dictionary of password hashes.
    
    Returns:
        dict: {username: {'hash': hash, 'last_change': last_change, ...}}
    """
    shadows = {}
    
    try:
        with open(shadow_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password_hash = parts[1]
                    
                    # Additional shadow fields
                    shadow_data = {
                        'hash': password_hash,
                        'last_change': parts[2] if len(parts) > 2 else '',
                        'min_days': parts[3] if len(parts) > 3 else '',
                        'max_days': parts[4] if len(parts) > 4 else '',
                        'warn_days': parts[5] if len(parts) > 5 else '',
                        'inactive_days': parts[6] if len(parts) > 6 else '',
                        'expire_date': parts[7] if len(parts) > 7 else '',
                    }
                    
                    shadows[username] = shadow_data
    except FileNotFoundError:
        print(f"[!] Error: {shadow_file} not found")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Error: Permission denied reading {shadow_file}")
        print("[!] Run with sudo to access shadow file")
        sys.exit(1)
    
    return shadows


def identify_hash_type(password_hash):
    """
    Identify the hash algorithm used.
    
    Returns:
        str: Hash type description
    """
    if not password_hash or password_hash in ('*', '!', '!!', ''):
        return "No password / Locked"
    
    if password_hash.startswith('$1$'):
        return "MD5"
    elif password_hash.startswith('$2a$') or password_hash.startswith('$2b$') or password_hash.startswith('$2y$'):
        return "Blowfish (bcrypt)"
    elif password_hash.startswith('$5$'):
        return "SHA-256"
    elif password_hash.startswith('$6$'):
        return "SHA-512"
    elif password_hash.startswith('$y$') or password_hash.startswith('$7$'):
        return "yescrypt"
    elif password_hash.startswith('$gy$'):
        return "gost-yescrypt"
    elif len(password_hash) == 13:
        return "DES (legacy)"
    else:
        return "Unknown"


def is_valid_hash(password_hash):
    """Check if the hash is a valid crackable hash (not locked/disabled)."""
    if not password_hash:
        return False
    if password_hash in ('*', '!', '!!', 'x', ''):
        return False
    if password_hash.startswith('!') or password_hash.startswith('*'):
        return False
    return True


def create_john_format(users, shadows, include_all=False, include_gecos=True):
    """
    Combine passwd and shadow data into John the Ripper format.
    
    Format: username:hash:uid:gid:gecos:home:shell
    
    Args:
        users: Dictionary from parse_passwd()
        shadows: Dictionary from parse_shadow()
        include_all: Include accounts without valid hashes
        include_gecos: Include GECOS field for wordlist generation
    
    Returns:
        list: Lines in John the Ripper format
    """
    john_lines = []
    stats = {
        'total': 0,
        'valid_hashes': 0,
        'locked': 0,
        'no_password': 0,
        'hash_types': {}
    }
    
    for username, user_data in users.items():
        stats['total'] += 1
        
        if username in shadows:
            shadow_data = shadows[username]
            password_hash = shadow_data['hash']
            hash_type = identify_hash_type(password_hash)
            
            # Track hash types
            stats['hash_types'][hash_type] = stats['hash_types'].get(hash_type, 0) + 1
            
            if is_valid_hash(password_hash):
                stats['valid_hashes'] += 1
                
                # Build the john format line
                if include_gecos:
                    line = f"{username}:{password_hash}:{user_data['uid']}:{user_data['gid']}:{user_data['gecos']}:{user_data['home']}:{user_data['shell']}"
                else:
                    line = f"{username}:{password_hash}"
                
                john_lines.append(line)
            else:
                if password_hash in ('*', '!', '!!'):
                    stats['locked'] += 1
                else:
                    stats['no_password'] += 1
                
                if include_all:
                    line = f"# {username}:{password_hash} (LOCKED/DISABLED)"
                    john_lines.append(line)
    
    return john_lines, stats


def extract_gecos_wordlist(users):
    """
    Extract potential password candidates from GECOS fields.
    
    GECOS often contains: Full Name, Room Number, Work Phone, Home Phone, Other
    These are commonly used as password bases.
    
    Returns:
        list: Potential wordlist entries
    """
    wordlist = set()
    
    for username, user_data in users.items():
        gecos = user_data.get('gecos', '')
        
        if gecos:
            # Add the full GECOS field
            wordlist.add(gecos)
            
            # Split by comma (standard GECOS separator)
            for part in gecos.split(','):
                part = part.strip()
                if part:
                    wordlist.add(part)
                    
                    # Split names into individual words
                    for word in part.split():
                        word = word.strip()
                        if len(word) > 2:  # Skip very short words
                            wordlist.add(word)
                            wordlist.add(word.lower())
                            wordlist.add(word.upper())
                            wordlist.add(word.capitalize())
        
        # Also add username variations
        wordlist.add(username)
        wordlist.add(username.capitalize())
        wordlist.add(username.upper())
    
    return sorted(wordlist)


def write_output(lines, output_file):
    """Write lines to output file."""
    try:
        with open(output_file, 'w') as f:
            for line in lines:
                f.write(line + '\n')
        return True
    except IOError as e:
        print(f"[!] Error writing to {output_file}: {e}")
        return False


def print_stats(stats):
    """Print extraction statistics."""
    print("\n" + "="*50)
    print("EXTRACTION STATISTICS")
    print("="*50)
    print(f"Total accounts processed: {stats['total']}")
    print(f"Valid password hashes:    {stats['valid_hashes']}")
    print(f"Locked accounts:          {stats['locked']}")
    print(f"No password set:          {stats['no_password']}")
    print("\nHash types found:")
    for hash_type, count in sorted(stats['hash_types'].items()):
        print(f"  {hash_type}: {count}")
    print("="*50)


def interactive_mode():
    """Run in interactive mode, prompting for options."""
    print("\n" + "="*50)
    print("Shadow/Passwd Hash Extractor for John the Ripper")
    print("="*50 + "\n")
    
    # Get output filename
    while True:
        output_file = input("Enter output filename (e.g., hashes.txt): ").strip()
        if output_file:
            break
        print("[!] Please enter a valid filename")
    
    # Ask about options
    include_gecos = input("Include GECOS fields for wordlist hints? (Y/n): ").strip().lower() != 'n'
    generate_wordlist = input("Generate GECOS-based wordlist? (y/N): ").strip().lower() == 'y'
    filter_system = input("Filter out system accounts (UID < 1000)? (Y/n): ").strip().lower() != 'n'
    
    return {
        'output_file': output_file,
        'include_gecos': include_gecos,
        'generate_wordlist': generate_wordlist,
        'filter_system': filter_system,
        'min_uid': 1000 if filter_system else 0
    }


def main():
    parser = argparse.ArgumentParser(
        description='Extract password hashes from /etc/shadow for John the Ripper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 %(prog)s -o hashes.txt
  sudo python3 %(prog)s -o hashes.txt --wordlist words.txt
  sudo python3 %(prog)s -o hashes.txt --min-uid 1000 --no-gecos
  sudo python3 %(prog)s --interactive
        """
    )
    
    parser.add_argument('-o', '--output', help='Output file for John the Ripper format')
    parser.add_argument('-w', '--wordlist', help='Generate GECOS-based wordlist to this file')
    parser.add_argument('--passwd', default='/etc/passwd', help='Path to passwd file (default: /etc/passwd)')
    parser.add_argument('--shadow', default='/etc/shadow', help='Path to shadow file (default: /etc/shadow)')
    parser.add_argument('--min-uid', type=int, default=0, help='Minimum UID to include (use 1000 to filter system accounts)')
    parser.add_argument('--no-gecos', action='store_true', help='Exclude GECOS field from output')
    parser.add_argument('--include-locked', action='store_true', help='Include locked/disabled accounts (commented)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Check for root
    check_root()
    
    # Interactive mode
    if args.interactive or (not args.output and not args.wordlist):
        options = interactive_mode()
        args.output = options['output_file']
        args.min_uid = options['min_uid']
        if options['generate_wordlist']:
            args.wordlist = Path(args.output).stem + '_wordlist.txt'
        args.no_gecos = not options['include_gecos']
    
    if not args.output:
        print("[!] Error: Output file required. Use -o or --interactive")
        sys.exit(1)
    
    print(f"\n[*] Reading {args.passwd}...")
    users = parse_passwd(args.passwd)
    print(f"[+] Found {len(users)} user accounts")
    
    print(f"[*] Reading {args.shadow}...")
    shadows = parse_shadow(args.shadow)
    print(f"[+] Found {len(shadows)} shadow entries")
    
    # Filter by UID if specified
    if args.min_uid > 0:
        original_count = len(users)
        users = {u: d for u, d in users.items() if int(d['uid']) >= args.min_uid}
        print(f"[*] Filtered to {len(users)} users with UID >= {args.min_uid}")
    
    # Create John format
    print("[*] Generating John the Ripper format...")
    john_lines, stats = create_john_format(
        users, shadows,
        include_all=args.include_locked,
        include_gecos=not args.no_gecos
    )
    
    # Write main output
    if write_output(john_lines, args.output):
        print(f"[+] Wrote {len(john_lines)} entries to {args.output}")
    
    # Generate wordlist if requested
    if args.wordlist:
        print("[*] Generating GECOS-based wordlist...")
        wordlist = extract_gecos_wordlist(users)
        if write_output(wordlist, args.wordlist):
            print(f"[+] Wrote {len(wordlist)} wordlist entries to {args.wordlist}")
    
    # Print statistics
    print_stats(stats)
    
    # Usage hints
    print("\n[*] Usage with John the Ripper:")
    print(f"    john {args.output}")
    print(f"    john --wordlist=rockyou.txt {args.output}")
    if args.wordlist:
        print(f"    john --wordlist={args.wordlist} {args.output}")
    print(f"    john --show {args.output}")


if __name__ == '__main__':
    main()