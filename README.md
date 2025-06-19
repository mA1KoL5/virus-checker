# VirusTotal File Integrity Checker

This script scans a directory, calculates SHA-256 hashes for all files, and checks for unexpected changes. New or modified files are looked up using the VirusTotal API to identify potential threats.

## Skills Demonstrated

- Tracks file additions, deletions, and modifications using secure SHA-256 hashing
- Interacts with the VirusTotal API to enrich findings with real-world threat intelligence
- Implements Python scripting using modules like `pathlib`, `hashlib`, `requests`, and `argparse`
- Handles environment variables securely with `.env` files to avoid hardcoding sensitive keys
- Resolves Windows `.lnk` shortcut targets (platform-aware behavior)
- Skips unreadable system files with graceful error handling
- Supports cross-platform compatibility (Windows, Linux, macOS)

### Implementations

This tool reflects key practices used in blue team operations and incident response. File integrity monitoring is a required control in many security frameworks (e.g., NIST, PCI-DSS, HIPAA). By automatically tracking file changes and validating them through VirusTotal, this script can help detect tampering, malware implants, and suspicious behavior in monitored directories.
## How It Works

This tool monitors a directory for unexpected file changes by:

1. **Computing SHA-256 hashes**  
   It scans all files in the target folder and calculates their SHA-256 hash values. These hashes uniquely represent each file’s content.

2. **Saving a trusted baseline**  
   On the first run, it creates a `trusted_hashes.json` file to store the original state of all scanned files.

3. **Detecting changes**  
   On later runs, it compares current file hashes with the baseline:
   - New files are marked as **added**
   - Missing files are **deleted**
   - Changed hashes mean the file was **modified**

4. **Checking with VirusTotal**  
   Any added or modified file is checked against the [VirusTotal](https://virustotal.com) API using its SHA-256 hash. The script displays:
   - `Clean` → no detections
   - `X detections` → flagged by AV engines
   - `Unknown` → not seen before in VirusTotal

5. **Logging & Summary**  
   Each run updates the baseline, prints results in color-coded format, and shows a summary at the end.

## Features
- Tracks file additions, deletions, and changes
- Sends hashes to VirusTotal for reputation scoring
- Resolves Windows `.lnk` shortcut targets
- Saves trusted hash database locally (`trusted_hashes.json`)
- Works on Windows, Linux, and macOS

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # insert your VirusTotal API key

## Example Output

Here's a scan showing one detection flagged by VirusTotal:
```
## Output

![Scan output screenshot](image_2025-06-18_195900270.png)
