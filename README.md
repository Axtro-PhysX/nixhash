# nixhash

Extracts password hashes from `/etc/shadow` and combines them with `/etc/passwd` data for use with John the Ripper.

## Requirements

- Python 3.6+
- Root privileges (to read `/etc/shadow`)

## Usage

```bash
# Interactive mode
sudo python3 dump.py

# Basic extraction
sudo python3 dump.py -o hashes.txt

# Filter to real users only (UID >= 1000)
sudo python3 dump.py -o hashes.txt --min-uid 1000

# Generate a wordlist from GECOS fields
sudo python3 dump.py -o hashes.txt --wordlist words.txt

# Offline analysis (copied files from another system)
sudo python3 dump.py --passwd ./passwd.bak --shadow ./shadow.bak -o hashes.txt
```

## Options

```
-o, --output        Output file for John the Ripper format
-w, --wordlist      Generate GECOS-based wordlist to this file
--passwd            Path to passwd file (default: /etc/passwd)
--shadow            Path to shadow file (default: /etc/shadow)
--min-uid           Minimum UID to include (1000 filters out system accounts)
--no-gecos          Exclude GECOS field from output
--include-locked    Include locked/disabled accounts (commented out)
-i, --interactive   Run in interactive mode
-v, --verbose       Verbose output
```

## Output Format

Standard John the Ripper format:
```
username:$6$salt$hash:uid:gid:GECOS:home:shell
```

## Using with John

```bash
# Default attack
john hashes.txt

# With wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# With generated GECOS wordlist
john --wordlist=words.txt --rules hashes.txt

# Show cracked passwords
john --show hashes.txt
```

## Supported Hash Types

- DES (legacy)
- MD5 (`$1$`)
- Blowfish/bcrypt (`$2a$`, `$2b$`, `$2y$`)
- SHA-256 (`$5$`)
- SHA-512 (`$6$`)
- yescrypt (`$y$`, `$7$`)

## Platform Support

Works on Linux and Solaris. BSD systems use `/etc/master.passwd` with a different format and are not currently supported.

## License

MIT