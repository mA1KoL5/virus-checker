#!/usr/bin/env python3
"""
VirusTotal-Backed File Integrity Checker
- Computes SHA-256 of all files in a given directory
- Checks new or changed files against VirusTotal
- Saves trusted hashes in a local JSON database
- Gracefully skips unreadable files
"""

import os, json, hashlib, argparse, requests, platform
from pathlib import Path
from dotenv import load_dotenv

try:
    import win32com.client
except ImportError:
    win32com = None

from colorama import Fore, Style, init as color_init
color_init()
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
HASH_DB = "trusted_hashes.json"

def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Cannot read: {file_path} ({e}){Style.RESET_ALL}")
        return None

def resolve_shortcut(path: Path) -> Path:
    if platform.system() == "Windows" and path.suffix.lower() == ".lnk" and win32com:
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortcut(str(path))
            return Path(shortcut.TargetPath)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to resolve shortcut: {path} ({e}){Style.RESET_ALL}")
    return path

def vt_lookup(file_hash: str) -> str:
    if not VT_API_KEY:
        return "NO_API_KEY"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(VT_URL.format(file_hash), headers=headers)
    if r.status_code == 200:
        data = r.json()
        score = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return f"{score} detections" if score > 0 else "Clean"
    elif r.status_code == 404:
        return "Unknown"
    else:
        return f"VT error {r.status_code}"

def load_hashes() -> dict:
    if Path(HASH_DB).exists():
        return json.loads(Path(HASH_DB).read_text())
    return {}

def save_hashes(hashes: dict) -> None:
    Path(HASH_DB).write_text(json.dumps(hashes, indent=2))

def scan_dir(directory: Path) -> dict:
    results = {}
    for file in directory.rglob("*"):
        if file.is_file():
            real_path = resolve_shortcut(file)
            if real_path.exists():
                result = compute_sha256(real_path)
                if result:
                    results[str(file.resolve())] = result
    return results

def compare_and_check(dir_path: Path):
    previous = load_hashes()
    current = scan_dir(dir_path)

    added = current.keys() - previous.keys()
    deleted = previous.keys() - current.keys()
    changed = {p for p in current if p in previous and current[p] != previous[p]}

    results = {}

    for p in sorted(added):
        vt = vt_lookup(current[p])
        print(f"{Fore.GREEN}[+] ADDED     {p} | {vt}{Style.RESET_ALL}")
        results[p] = {"hash": current[p], "status": vt}

    for p in sorted(deleted):
        print(f"{Fore.RED}[-] DELETED   {p}{Style.RESET_ALL}")

    for p in sorted(changed):
        vt = vt_lookup(current[p])
        print(f"{Fore.YELLOW}[∗] MODIFIED  {p} | {vt}{Style.RESET_ALL}")
        results[p] = {"hash": current[p], "status": vt}

    print(f"\nSummary: {len(added)} added, {len(deleted)} deleted, {len(changed)} modified")
    save_hashes(current)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal File Integrity Checker")
    parser.add_argument("directory", help="Path to directory to scan")
    args = parser.parse_args()

    dir_path = Path(args.directory).resolve()
    if not dir_path.exists():
        print(f"{Fore.RED}Directory not found: {dir_path}{Style.RESET_ALL}")
        exit(1)

    print(f"Scanning: {dir_path}\n")
    compare_and_check(dir_path)
