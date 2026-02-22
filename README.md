# duplicate_finder

Recursively scans a directory for duplicate files, moves them to a designated folder, and writes a plain-text report.

Available as:
- **`duplicate_finder.py`** — Python 3.10+, cross-platform (macOS / Linux / Windows)
- **`duplicate_finder.ps1`** — PowerShell 5.1+, Windows only, no Python required
- **`duplicate_finder.bat`** — thin Command Prompt launcher for the PowerShell script

## What counts as a duplicate?

A file is a **duplicate** if another file with the **same extension** (e.g. `.pdf`) and the **same content hash** has already been encountered during the scan. The first occurrence is kept as the original; every subsequent match is treated as a duplicate.

## Requirements

| Script | Requirement |
|---|---|
| `duplicate_finder.py` | Python 3.10 or newer — no third-party packages |
| `duplicate_finder.ps1` | PowerShell 5.1 or newer (built into Windows 10/11) — no Python |
| `duplicate_finder.bat` | Any Windows Command Prompt — delegates to the `.ps1` |

---

## Python usage (macOS / Linux / Windows)

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
| `--preview-file` | no | off | Write a preview report file when using `--dry-run` (named `duplicates_report_preview_<timestamp>.txt`); has no effect without `--dry-run` |
| `--filter-ext EXT [EXT ...]` | no | all files | Only scan files with the given extension(s); leading dot is optional |

### Examples

```bash
# Basic scan — move duplicates to ./duplicates/
python duplicate_finder.py ~/Downloads

# Custom output folder
python duplicate_finder.py ~/Documents --output-dir ~/Desktop/dupes

# Preview only (nothing is moved, preview printed to stdout)
python duplicate_finder.py ~/Downloads --output-dir ~/dupes --dry-run

# Preview and also save a preview report file
python duplicate_finder.py ~/Downloads --output-dir ~/dupes --dry-run --preview-file

# Faster scan with MD5 (less collision-resistant, fine for most use cases)
python duplicate_finder.py /data/photos --output-dir /data/dupes --hash-algo md5

# Only look for duplicate PDFs
python duplicate_finder.py ~/Documents --output-dir ~/dupes --filter-ext .pdf

# Only look for duplicate PDFs and Word documents
python duplicate_finder.py ~/Documents --output-dir ~/dupes --filter-ext .pdf .doc .docx

# Dry-run scoped to images only
python duplicate_finder.py ~/Photos --output-dir ~/dupes --filter-ext .jpg .png --dry-run
```

---

## PowerShell usage (Windows — no Python required)

```
.\duplicate_finder.ps1 <SourceDir> [options]
```

If script execution is blocked, run once from an elevated PowerShell prompt:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Or use the `.bat` launcher which bypasses the policy automatically:
```
duplicate_finder.bat <SourceDir> [options]
```

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `SourceDir` | yes | — | Directory to scan recursively |
| `-OutputDir` | no | `.\duplicates` | Where duplicates are moved; report is also written here |
| `-HashAlgo` | no | `SHA256` | Hash algorithm: `MD5`, `SHA1`, or `SHA256` |
| `-DryRun` | no | off | Preview actions without moving any files |
| `-PreviewFile` | no | off | Write a preview report file when using `-DryRun`; has no effect without `-DryRun` |
| `-FilterExt` | no | all files | Only scan files with the given extension(s); leading dot is optional |

### Examples

```powershell
# Basic scan — move duplicates to .\duplicates\
.\duplicate_finder.ps1 C:\Downloads

# Custom output folder
.\duplicate_finder.ps1 C:\Documents -OutputDir C:\Desktop\Dupes

# Preview only (nothing is moved, preview printed to console)
.\duplicate_finder.ps1 C:\Downloads -OutputDir C:\Dupes -DryRun

# Preview and also save a preview report file
.\duplicate_finder.ps1 C:\Downloads -OutputDir C:\Dupes -DryRun -PreviewFile

# Faster scan with MD5
.\duplicate_finder.ps1 C:\Photos -OutputDir C:\Dupes -HashAlgo MD5

# Only look for duplicate PDFs
.\duplicate_finder.ps1 C:\Documents -OutputDir C:\Dupes -FilterExt .pdf

# Only look for duplicate PDFs and Word documents
.\duplicate_finder.ps1 C:\Documents -OutputDir C:\Dupes -FilterExt .pdf .doc .docx

# Dry-run scoped to images only
.\duplicate_finder.ps1 C:\Photos -OutputDir C:\Dupes -FilterExt .jpg .png -DryRun
```

Same examples via the `.bat` launcher from Command Prompt:
```
duplicate_finder.bat C:\Downloads
duplicate_finder.bat C:\Downloads -OutputDir C:\Dupes -DryRun -PreviewFile
duplicate_finder.bat C:\Downloads -FilterExt .pdf .doc -DryRun
```

## Output

After running, inside `--output-dir` you will find:

1. **The moved duplicate files** — original filenames are preserved; if two duplicates share the same name, a numeric suffix is appended (e.g. `photo_1.jpg`).
2. **`duplicates_report.txt`** — one line per original file that had duplicates, with all duplicate full paths listed as CSV on the right:

```
ORIGINAL: /Users/alice/Documents/invoices/invoice.pdf  |  DUPLICATE: /Users/alice/Downloads/invoice.pdf, /Users/alice/Desktop/invoice.pdf
ORIGINAL: /Users/alice/Work/notes.docx  |  DUPLICATE: /Users/alice/backup/notes.docx
```

When `--dry-run` is used, the preview is printed to stdout:

```
--- Report preview ---
ORIGINAL: /Users/alice/Documents/invoice.pdf  |  DUPLICATE: /Users/alice/Downloads/invoice.pdf
```

Add `--preview-file` to also save the preview to disk:

```
[DRY-RUN] Preview report written to: /Users/alice/dupes/duplicates_report_preview_2026_02_22_12_00_00.txt

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