#!/usr/bin/env python3
"""
Notepad++ Release Hash Collector
Scrapes all GitHub releases and extracts checksum hashes from checksum files.
"""

import requests
import json
import csv
import re
import time
import random
import os
from datetime import datetime, timezone
from pathlib import Path

# Configuration
REPO_OWNER = "notepad-plus-plus"
REPO_NAME = "notepad-plus-plus"
OUTPUT_DIR = Path("/home/neo/clawd/projects/notepad-pp-hashes")

# Checksum file patterns (case insensitive matching)
CHECKSUM_PATTERNS = [
    r'.*\.checksums\.sha256$',
    r'.*\.sha256$',
    r'.*checksum.*sha256.*',
]

# Signature file patterns (for reference, not parsed)
SIGNATURE_PATTERNS = [
    r'.*\.sig$',
    r'.*\.asc$',
]

class RateLimitHandler:
    """Handles GitHub API rate limiting with exponential backoff."""
    
    def __init__(self):
        self.token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
        self.headers = {}
        if self.token:
            self.headers['Authorization'] = f'token {self.token}'
            print(f"✓ Using GitHub token (first 4 chars: {self.token[:4]}...)")
        else:
            print("⚠ No GitHub token found. Using unauthenticated requests (60/hr limit).")
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.headers.update({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'NotepadPP-Hash-Collector/1.0'
        })
    
    def make_request(self, url, max_retries=5):
        """Make a request with rate limit handling."""
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, timeout=30)
                
                # Check for rate limiting
                if response.status_code == 403:
                    remaining = response.headers.get('X-RateLimit-Remaining')
                    reset_time = response.headers.get('X-RateLimit-Reset')
                    
                    if remaining == '0' and reset_time:
                        reset_ts = int(reset_time)
                        sleep_time = max(reset_ts - int(time.time()), 0) + 1
                        print(f"  ⏳ Rate limit hit. Sleeping until reset ({sleep_time}s)...")
                        time.sleep(sleep_time)
                        continue
                    
                    # Secondary rate limit - exponential backoff with jitter
                    if 'secondary rate limit' in response.text.lower() or attempt < max_retries - 1:
                        sleep_time = (2 ** attempt) + random.uniform(1, 3)
                        print(f"  ⏳ Secondary rate limit or 403. Backoff {sleep_time:.1f}s...")
                        time.sleep(sleep_time)
                        continue
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    sleep_time = (2 ** attempt) + random.uniform(1, 3)
                    print(f"  ⚠ Request error: {e}. Retry {attempt+1}/{max_retries} in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)
                else:
                    raise
        
        raise Exception(f"Failed after {max_retries} attempts: {url}")
    
    def download_asset(self, url):
        """Download an asset file (no rate limit concerns for raw downloads with auth)."""
        response = self.session.get(url, timeout=60)
        response.raise_for_status()
        return response.text


class ChecksumParser:
    """Parses various checksum file formats."""
    
    # Hash length to algorithm mapping
    HASH_LENGTHS = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }
    
    @staticmethod
    def detect_algorithm(hex_string):
        """Detect hash algorithm from hex string length."""
        return ChecksumParser.HASH_LENGTHS.get(len(hex_string), 'unknown')
    
    @staticmethod
    def parse(content):
        """
        Parse checksum file content.
        Returns list of dicts with hash_value and inferred_asset_name.
        """
        hashes = []
        anomalies = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            parsed = ChecksumParser._try_parse_line(line)
            if parsed:
                parsed['line_number'] = line_num
                hashes.append(parsed)
            elif len(line) > 32 and re.search(r'[a-f0-9]{32,}', line.lower()):
                # Line looks like it might have a hash but couldn't parse
                anomalies.append({
                    'line_number': line_num,
                    'line_preview': line[:100]
                })
        
        return hashes, anomalies
    
    @staticmethod
    def _try_parse_line(line):
        """Try to parse a single line in various formats (supports md5, sha1, sha256, etc)."""
        
        # Generic hex hash detection for common lengths
        hex_patterns = [
            (32, 'md5'),    # MD5: 32 hex chars
            (40, 'sha1'),   # SHA1: 40 hex chars
            (64, 'sha256'), # SHA256: 64 hex chars
            (96, 'sha384'), # SHA384: 96 hex chars
            (128, 'sha512') # SHA512: 128 hex chars
        ]
        
        for hex_len, algo in hex_patterns:
            # Format 1: "<hex>  filename" (standard *sum output)
            # Format 2: "<hex> *filename" (binary mode *sum)
            pattern = rf'^([a-f0-9]{{{hex_len}}})\s+([ *]?)(.+)$'
            match = re.match(pattern, line.lower())
            if match:
                return {
                    'hash_value': match.group(1).lower(),
                    'inferred_asset_name': match.group(3).strip(),
                    'hash_algorithm': algo
                }
            
            # Format: "ALGO(filename)= <hex>" (OpenSSL style)
            openssl_pattern = rf'^{algo}\(([^)]+)\)=\s*([a-f0-9]{{{hex_len}}})$'
            match = re.match(openssl_pattern, line.lower())
            if match:
                return {
                    'hash_value': match.group(2).lower(),
                    'inferred_asset_name': match.group(1).strip(),
                    'hash_algorithm': algo
                }
            
            # Format: Just "<hex>" on its own (no filename)
            solo_pattern = rf'^([a-f0-9]{{{hex_len}}})$'
            match = re.match(solo_pattern, line.lower())
            if match:
                return {
                    'hash_value': match.group(1).lower(),
                    'inferred_asset_name': None,
                    'hash_algorithm': algo
                }
            
            # Format: "filename: <hex>" or "filename <hex>"
            rev_pattern = rf'^(.+?)[:\s]+([a-f0-9]{{{hex_len}}})$'
            match = re.match(rev_pattern, line.lower())
            if match:
                potential_name = match.group(1).strip()
                potential_hash = match.group(2)
                # Make sure the "filename" part isn't actually another hash
                if len(potential_name) < hex_len:
                    return {
                        'hash_value': potential_hash,
                        'inferred_asset_name': potential_name,
                        'hash_algorithm': algo
                    }
        
        return None


class NotepadPPHashCollector:
    """Main collector class."""
    
    def __init__(self):
        self.api = RateLimitHandler()
        self.parser = ChecksumParser()
        self.all_hashes = []
        self.releases_processed = 0
        self.releases_with_checksum = 0
        self.releases_without_checksum = 0
        self.total_anomalies = []
        self.release_details = []
    
    def fetch_all_releases(self):
        """Fetch all releases via pagination."""
        releases = []
        page = 1
        per_page = 100
        
        print("Fetching releases from GitHub API...")
        
        while True:
            url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases?per_page={per_page}&page={page}"
            print(f"  Page {page}...", end=' ', flush=True)
            
            response = self.api.make_request(url)
            page_releases = response.json()
            
            if not page_releases:
                print("done")
                break
            
            releases.extend(page_releases)
            print(f"got {len(page_releases)}")
            
            if len(page_releases) < per_page:
                break
            
            page += 1
            # Small delay between pages to be nice
            time.sleep(0.5)
        
        print(f"\nTotal releases found: {len(releases)}")
        return releases
    
    def find_checksum_assets(self, release):
        """Find checksum and signature assets in a release."""
        assets = release.get('assets', [])
        checksum_assets = []
        signature_assets = []
        
        for asset in assets:
            name_lower = asset['name'].lower()
            
            for pattern in CHECKSUM_PATTERNS:
                if re.match(pattern, name_lower, re.IGNORECASE):
                    checksum_assets.append(asset)
                    break
            
            for pattern in SIGNATURE_PATTERNS:
                if re.match(pattern, name_lower, re.IGNORECASE):
                    signature_assets.append(asset)
                    break
        
        return checksum_assets, signature_assets
    
    def parse_release_body(self, release):
        """Fallback: try to parse hashes from release body text."""
        body = release.get('body', '') or ''
        hashes = []
        
        # Look for digest sections with various algorithms
        # Patterns: "SHA-1 Digest:", "SHA256 Digest:", "MD5:", "## SHA256", etc.
        # Split on common hash section headers
        section_patterns = [
            r'(?:sha-?1|md5|sha-?256|sha-?384|sha-?512|checksum|digest)[\s\-]*(?:digest|hash)?:?\s*',
            r'##?\s*(?:sha-?1|md5|sha-?256|sha-?384|sha-?512|checksum)\s*',
        ]
        
        for pattern in section_patterns:
            sections = re.split(pattern, body, flags=re.IGNORECASE)
            for section in sections[1:] if len(sections) > 1 else []:
                lines = section.strip().split('\n')[:30]  # Check first 30 lines after header
                for line in lines:
                    line = line.strip()
                    # Stop if we hit empty lines or obvious non-hash content
                    if not line or line.startswith('##') or line.startswith('**'):
                        continue
                    # Stop if we hit a markdown header or link
                    if line.startswith('#') or line.startswith('['):
                        break
                    parsed = self.parser._try_parse_line(line)
                    if parsed:
                        hashes.append(parsed)
        
        # Also look for code blocks with hashes
        code_blocks = re.findall(r'```(?:\w*)?\n(.*?)```', body, re.DOTALL)
        for block in code_blocks:
            for line in block.split('\n'):
                parsed = self.parser._try_parse_line(line.strip())
                if parsed:
                    hashes.append(parsed)
        
        # Also scan for lines that look like hash entries anywhere in the body
        # This catches patterns like "5a1c712... npp.6.8.9.Installer.exe"
        for line in body.split('\n'):
            line = line.strip()
            parsed = self.parser._try_parse_line(line)
            if parsed:
                # Only add if we haven't seen this hash already
                if not any(h['hash_value'] == parsed['hash_value'] for h in hashes):
                    hashes.append(parsed)
        
        return hashes
    
    def process_release(self, release):
        """Process a single release."""
        tag = release['tag_name']
        title = release.get('name', tag)
        date = release.get('published_at', '')
        prerelease = release.get('prerelease', False)
        release_url = release.get('html_url', '')
        
        print(f"\n[{tag}] {title}")
        self.releases_processed += 1
        
        release_info = {
            'version_tag': tag,
            'release_title': title,
            'release_date': date,
            'prerelease': prerelease,
            'release_url': release_url,
        }
        
        checksum_assets, signature_assets = self.find_checksum_assets(release)
        
        if signature_assets:
            print(f"  Found {len(signature_assets)} signature file(s)")
        
        if checksum_assets:
            print(f"  Found {len(checksum_assets)} checksum file(s)")
            self.releases_with_checksum += 1
            
            for asset in checksum_assets:
                try:
                    print(f"    Downloading: {asset['name']}...", end=' ', flush=True)
                    content = self.api.download_asset(asset['browser_download_url'])
                    print("done")
                    
                    hashes, anomalies = self.parser.parse(content)
                    self.total_anomalies.extend([
                        {**a, 'release_tag': tag, 'asset_name': asset['name']} 
                        for a in anomalies
                    ])
                    
                    print(f"    Parsed {len(hashes)} hash(es)")
                    
                    for h in hashes:
                        self.all_hashes.append({
                            **release_info,
                            'hash_algorithm': h['hash_algorithm'],
                            'hash_value': h['hash_value'],
                            'inferred_asset_name': h['inferred_asset_name'],
                            'source_location': 'checksum_asset',
                            'checksum_asset_name': asset['name'],
                            'checksum_asset_url': asset['browser_download_url'],
                        })
                    
                    # Small delay between downloads
                    time.sleep(0.2)
                    
                except Exception as e:
                    print(f"ERROR: {e}")
                    self.total_anomalies.append({
                        'release_tag': tag,
                        'asset_name': asset['name'],
                        'error': str(e)
                    })
        else:
            print(f"  No checksum files. Trying release body fallback...", end=' ', flush=True)
            body_hashes = self.parse_release_body(release)
            
            if body_hashes:
                print(f"found {len(body_hashes)} hash(es)")
                self.releases_with_checksum += 1
                for h in body_hashes:
                    self.all_hashes.append({
                        **release_info,
                        'hash_algorithm': h['hash_algorithm'],
                        'hash_value': h['hash_value'],
                        'inferred_asset_name': h['inferred_asset_name'],
                        'source_location': 'release_body',
                        'checksum_asset_name': None,
                        'checksum_asset_url': None,
                    })
            else:
                print("none found")
                self.releases_without_checksum += 1
        
        self.release_details.append(release_info)
    
    def generate_outputs(self):
        """Generate all output files."""
        print("\n" + "="*60)
        print("GENERATING OUTPUT FILES")
        print("="*60)
        
        # CSV
        csv_path = OUTPUT_DIR / "notepadpp_release_hashes.csv"
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            if self.all_hashes:
                writer = csv.DictWriter(f, fieldnames=list(self.all_hashes[0].keys()))
                writer.writeheader()
                writer.writerows(self.all_hashes)
            print(f"✓ CSV: {csv_path} ({len(self.all_hashes)} rows)")
        
        # JSON
        json_path = OUTPUT_DIR / "notepadpp_release_hashes.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'repository': f"{REPO_OWNER}/{REPO_NAME}",
                    'total_hashes': len(self.all_hashes),
                },
                'hashes': self.all_hashes
            }, f, indent=2)
            print(f"✓ JSON: {json_path}")
        
        # Summary
        summary_path = OUTPUT_DIR / "summary.txt"
        self.write_summary(summary_path)
        print(f"✓ Summary: {summary_path}")
        
        # Run log
        log_path = OUTPUT_DIR / "run_log.txt"
        self.write_run_log(log_path)
        print(f"✓ Run Log: {log_path}")
    
    def write_summary(self, path):
        """Write summary report."""
        # Compute unique hashes
        hash_values = [h['hash_value'] for h in self.all_hashes]
        unique_hashes = set(hash_values)
        
        # Find duplicates
        from collections import Counter
        hash_counts = Counter(hash_values)
        duplicates = {h: c for h, c in hash_counts.items() if c > 1}
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("NOTEPAD++ RELEASE HASHES - SUMMARY REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"Repository: {REPO_OWNER}/{REPO_NAME}\n")
            f.write(f"GitHub URL: https://github.com/{REPO_OWNER}/{REPO_NAME}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("PROCESSING STATISTICS\n")
            f.write("-"*70 + "\n")
            f.write(f"Total releases processed:     {self.releases_processed}\n")
            f.write(f"Releases with checksum:       {self.releases_with_checksum}\n")
            f.write(f"Releases without checksum:    {self.releases_without_checksum}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("HASH STATISTICS\n")
            f.write("-"*70 + "\n")
            f.write(f"Total hash rows extracted:    {len(self.all_hashes)}\n")
            f.write(f"Unique hash values:           {len(unique_hashes)}\n")
            f.write(f"Duplicate hash entries:       {len(duplicates)}\n\n")
            
            if duplicates:
                f.write("-"*70 + "\n")
                f.write("DUPLICATE HASHES (same hash appears multiple times)\n")
                f.write("-"*70 + "\n")
                for h, count in sorted(duplicates.items(), key=lambda x: -x[1])[:20]:
                    f.write(f"  {h[:16]}... ({count} occurrences)\n")
                f.write("\n")
            
            if self.total_anomalies:
                f.write("-"*70 + "\n")
                f.write("PARSING ANOMALIES\n")
                f.write("-"*70 + "\n")
                f.write(f"Total anomalies: {len(self.total_anomalies)}\n\n")
                for a in self.total_anomalies[:30]:
                    if 'error' in a:
                        f.write(f"  Error in {a.get('release_tag', '?')} / {a.get('asset_name', '?')}: {a['error']}\n")
                    else:
                        f.write(f"  {a.get('release_tag', '?')} / {a.get('asset_name', '?')} line {a.get('line_number', '?')}: {a.get('line_preview', '?')[:60]}\n")
                f.write("\n")
            
            f.write("-"*70 + "\n")
            f.write("ALGORITHM BREAKDOWN\n")
            f.write("-"*70 + "\n")
            algos = {}
            for h in self.all_hashes:
                algos[h['hash_algorithm']] = algos.get(h['hash_algorithm'], 0) + 1
            for algo, count in sorted(algos.items(), key=lambda x: -x[1]):
                f.write(f"  {algo}: {count}\n")
            f.write("\n")
            
            f.write("-"*70 + "\n")
            f.write("SOURCE LOCATION BREAKDOWN\n")
            f.write("-"*70 + "\n")
            sources = {}
            for h in self.all_hashes:
                src = h['source_location']
                sources[src] = sources.get(src, 0) + 1
            for src, count in sorted(sources.items(), key=lambda x: -x[1]):
                f.write(f"  {src}: {count}\n")
            f.write("\n")
            
            f.write("="*70 + "\n")
    
    def write_run_log(self, path):
        """Write detailed run log."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("NOTEPAD++ RELEASE HASHES - RUN LOG\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Started: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"GitHub API Token: {'Present' if self.api.token else 'Not found'}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("RELEASES PROCESSED\n")
            f.write("-"*70 + "\n")
            for info in self.release_details:
                f.write(f"\n[{info['version_tag']}]\n")
                f.write(f"  Title: {info['release_title']}\n")
                f.write(f"  Date: {info['release_date']}\n")
                f.write(f"  Prerelease: {info['prerelease']}\n")
                f.write(f"  URL: {info['release_url']}\n")
                
                # Find hashes for this release
                release_hashes = [h for h in self.all_hashes if h['version_tag'] == info['version_tag']]
                f.write(f"  Hashes extracted: {len(release_hashes)}\n")
                for h in release_hashes[:5]:  # Show first 5
                    asset = h['inferred_asset_name'] or 'unknown'
                    f.write(f"    - {h['hash_value'][:16]}... ({asset[:40]})\n")
                if len(release_hashes) > 5:
                    f.write(f"    ... and {len(release_hashes) - 5} more\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write(f"Finished: {datetime.now(timezone.utc).isoformat()}\n")
    
    def run(self):
        """Main entry point."""
        print("="*60)
        print("NOTEPAD++ RELEASE HASH COLLECTOR")
        print("="*60)
        print(f"Output directory: {OUTPUT_DIR}")
        print()
        
        # Fetch all releases
        releases = self.fetch_all_releases()
        
        # Process each release
        print("\nProcessing releases...")
        for release in releases:
            try:
                self.process_release(release)
            except Exception as e:
                print(f"ERROR processing {release.get('tag_name', '?')}: {e}")
                continue
        
        # Generate outputs
        self.generate_outputs()
        
        print("\n" + "="*60)
        print("COMPLETE!")
        print("="*60)
        print(f"Total releases: {self.releases_processed}")
        print(f"With checksums: {self.releases_with_checksum}")
        print(f"Without checksums: {self.releases_without_checksum}")
        print(f"Total hashes: {len(self.all_hashes)}")


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    collector = NotepadPPHashCollector()
    collector.run()
