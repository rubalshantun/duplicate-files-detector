# duplicate_finder

A zero-dependency Python CLI tool that recursively scans a directory for duplicate files, moves them to a designated folder, and writes a plain-text report.

## What counts as a duplicate?

A file is a **duplicate** if another file with the **same extension** (e.g. `.pdf`) and the **same content hash** has already been encountered during the scan. The first occurrence is kept as the original; every subsequent match is treated as a duplicate.

## Requirements

- Python 3.10 or newer (uses `match`-free walrus operator and `str | None` union syntax)
- No third-party packages required

## Usage

```
python duplicate_finder.py <source_dir> [options]
```

### Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `source_dir` | yes | — | Directory to scan recursively |
| `--output-dir DIR` | no | `./duplicates` | Where duplicates are moved; report is also written here |
| `--hash-algo ALGO` | no | `sha256` | Hash algorithm: `md5`, `sha1`, or `sha256` |
| `--dry-run` | no | off | Preview actions without moving any files |
| `--filter-ext EXT [EXT ...]` | no | all files | Only scan files with the given extension(s); leading dot is optional |

### Examples

```bash
# Basic scan — move duplicates to ./duplicates/
python duplicate_finder.py ~/Downloads

# Custom output folder
python duplicate_finder.py ~/Documents --output-dir ~/Desktop/dupes

# Preview only (nothing is moved)
python duplicate_finder.py ~/Downloads --output-dir ~/dupes --dry-run

# Faster scan with MD5 (less collision-resistant, fine for most use cases)
python duplicate_finder.py /data/photos --output-dir /data/dupes --hash-algo md5

# Only look for duplicate PDFs
python duplicate_finder.py ~/Documents --output-dir ~/dupes --filter-ext .pdf

# Only look for duplicate PDFs and Word documents
python duplicate_finder.py ~/Documents --output-dir ~/dupes --filter-ext .pdf .doc .docx

# Dry-run scoped to images only
python duplicate_finder.py ~/Photos --output-dir ~/dupes --filter-ext .jpg .png --dry-run
```

## Output

After running, inside `--output-dir` you will find:

1. **The moved duplicate files** — original filenames are preserved; if two duplicates share the same name, a numeric suffix is appended (e.g. `photo_1.jpg`).
2. **`duplicates_report.txt`** — one line per original file that had duplicates, with all duplicate full paths listed as CSV on the right:

```
ORIGINAL: /Users/alice/Documents/invoices/invoice.pdf  |  DUPLICATE: /Users/alice/Downloads/invoice.pdf, /Users/alice/Desktop/invoice.pdf
ORIGINAL: /Users/alice/Work/notes.docx  |  DUPLICATE: /Users/alice/backup/notes.docx
```

When `--dry-run` is used, the report is printed to stdout instead of written to disk:

```
[DRY-RUN] Report would be written to: /Users/alice/dupes/duplicates_report.txt

--- Report preview ---
ORIGINAL: /Users/alice/Documents/invoice.pdf  |  DUPLICATE: /Users/alice/Downloads/invoice.pdf
```

## Summary output

At the end of every run the tool prints a summary:

```
==================================================
Files scanned : 1024
Duplicates    : 37
Moved to      : /Users/alice/duplicates
==================================================
```