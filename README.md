# Notepad++ Release Hashes

A comprehensive collection of cryptographic hashes for all Notepad++ releases available on GitHub.

## Overview

This repository contains a complete, machine-readable dataset of hashes for Notepad++ installer and portable packages spanning from 2016 to present. The data was collected from the official [notepad-plus-plus/notepad-plus-plus](https://github.com/notepad-plus-plus/notepad-plus-plus) GitHub releases.

## Statistics

- **Total Releases Processed**: 134
- **Releases with Hash Data**: 124 (92.5%)
- **Releases Without Hashes**: 10 (mostly very old releases with no published checksums)
- **Total Hash Entries**: 1,449
- **Unique Hashes**: 1,373
- **Date Range**: 2016-01-13 (v6.7.9) to 2026-01-26 (v8.9.1)

### Hash Algorithms

| Algorithm | Count | Description |
|-----------|-------|-------------|
| SHA-256 | 933 | Primary algorithm used in modern releases (v7.5+) with `.checksums.sha256` files |
| SHA-1 | 332 | Used in older releases (v6.x - v7.4) via release notes |
| MD5 | 184 | Legacy algorithm from early releases via release notes |

### Source Breakdown

| Source | Count | Description |
|--------|-------|-------------|
| checksum_asset | 893 | Downloaded from official `.checksums.sha256` files |
| release_body | 556 | Parsed from release notes/descriptions |

## Files

### Data Files

| File | Format | Description |
|------|--------|-------------|
| `notepadpp_release_hashes.csv` | CSV | All hashes in tabular format with metadata |
| `notepadpp_release_hashes.json` | JSON | All hashes with structured metadata |
| `summary.txt` | Text | Human-readable summary and statistics |
| `run_log.txt` | Text | Detailed processing log per release |

### CSV Schema

The CSV file contains the following columns:

| Column | Description |
|--------|-------------|
| `version_tag` | Release version (e.g., `v8.9.1`) |
| `release_title` | Human-readable release title |
| `release_date` | ISO 8601 timestamp of release publication |
| `prerelease` | Boolean indicating if this was a pre-release |
| `release_url` | Direct link to the GitHub release page |
| `hash_algorithm` | Algorithm used (`sha256`, `sha1`, `md5`) |
| `hash_value` | The actual hash value (lowercase hex) |
| `inferred_asset_name` | Filename of the asset this hash corresponds to |
| `source_location` | Where the hash was found (`checksum_asset` or `release_body`) |
| `checksum_asset_name` | Name of the checksum file (if applicable) |
| `checksum_asset_url` | Direct download URL for the checksum file (if applicable) |

### JSON Structure

```json
{
  "metadata": {
    "generated_at": "2026-02-02T11:47:37Z",
    "repository": "notepad-plus-plus/notepad-plus-plus",
    "total_hashes": 1449
  },
  "hashes": [
    {
      "version_tag": "v8.9.1",
      "release_title": "Notepad++ release 8.9.1",
      "release_date": "2026-01-26T14:52:34Z",
      "prerelease": false,
      "release_url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.1",
      "hash_algorithm": "sha256",
      "hash_value": "85ea19609edb04ba320380fe81cde1e236a495633ba72c74734022d96efc8e1c",
      "inferred_asset_name": "npp.8.9.1.installer.arm64.exe",
      "source_location": "checksum_asset",
      "checksum_asset_name": "npp.8.9.1.checksums.sha256",
      "checksum_asset_url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.1/npp.8.9.1.checksums.sha256"
    }
  ]
}
```

## Usage Examples

### Verify a Download

```bash
# Linux/macOS
sha256sum -c <(echo "85ea19609edb04ba320380fe81cde1e236a495633ba72c74734022d96efc8e1c  npp.8.9.1.installer.arm64.exe")

# Or manually compare
echo "85ea19609edb04ba320380fe81cde1e236a495633ba72c74734022d96efc8e1c  npp.8.9.1.installer.arm64.exe" | sha256sum -c
```

### Query the Dataset

```bash
# Find all hashes for a specific version
grep "v8.9.1" notepadpp_release_hashes.csv

# Find SHA-256 hashes only
grep "sha256" notepadpp_release_hashes.csv

# Find hashes from release notes (older releases)
grep "release_body" notepadpp_release_hashes.csv
```

### Python Example

```python
import csv
import json

# Load CSV
with open('notepadpp_release_hashes.csv', 'r') as f:
    reader = csv.DictReader(f)
    hashes = list(reader)

# Find all hashes for a specific file
installer_hashes = [h for h in hashes if 'installer.exe' in h['inferred_asset_name']]

# Check if a specific hash exists
target_hash = "85ea19609edb04ba320380fe81cde1e236a495633ba72c74734022d96efc8e1c"
found = any(h['hash_value'] == target_hash for h in hashes)
```

## Collection Methodology

### Process

1. **API Enumeration**: All 134 releases were enumerated using the GitHub API
2. **Asset Discovery**: Each release was checked for checksum files matching patterns:
   - `*.checksums.sha256`
   - `*.sha256`
   - `*checksum*sha256*`
3. **Checksum Parsing**: SHA-256 checksum files were downloaded and parsed
4. **Fallback Extraction**: For releases without checksum files, the release body/description was parsed for:
   - SHA-256 hashes (64 hex characters)
   - SHA-1 hashes (40 hex characters) 
   - MD5 hashes (32 hex characters)
5. **Deduplication**: Duplicate hash entries were tracked but preserved in the dataset

### Supported Hash Formats

The parser handles multiple checksum file formats:
- `<hash>  <filename>` (standard *sum output)
- `<hash> *<filename>` (binary mode *sum)
- `<algorithm>(<filename>)= <hash>` (OpenSSL style)
- `<filename>: <hash>` or `<filename> <hash>` (inline style)

### Rate Limiting

The collection script respects GitHub API rate limits:
- Uses exponential backoff with jitter for 403/secondary rate limits
- Sleeps until `X-RateLimit-Reset` when primary rate limit is hit
- Small delays between requests to be API-friendly

## Data Quality Notes

### Duplicate Hashes

76 hash values appear multiple times in the dataset. This typically occurs when:
- The same file is referenced in both a checksum file and release notes
- Build artifacts produce identical binaries across minor version bumps
- Parser extracted the same hash from multiple sources

All duplicates are preserved to maintain data lineage.

### Missing Data

10 releases have no hash data available:
- Very old releases (v6.x era) where no checksums were published
- Some early v8.x releases where checksum files were temporarily omitted

See `run_log.txt` for specific releases without hash data.

### Hash Algorithm Evolution

| Era | Primary Algorithm | Source |
|-----|-------------------|--------|
| v6.x - v7.4 | SHA-1 / MD5 | Release notes (manual) |
| v7.5+ | SHA-256 | `*.checksums.sha256` files |

## Attribution

- **Source Repository**: [notepad-plus-plus/notepad-plus-plus](https://github.com/notepad-plus-plus/notepad-plus-plus)
- **Project Website**: <https://notepad-plus-plus.org/>
- **Data Generated**: 2026-02-02

Notepad++ is developed by Don Ho and contributors. This dataset is provided for verification and security research purposes.

## License

The hash data itself is factual information derived from publicly available Notepad++ releases. The collection script and this documentation are provided under the MIT License.

---

*Generated by automated collection script - see `collect_hashes.py` for implementation details.*
