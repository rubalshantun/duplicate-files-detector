#!/usr/bin/env python3
"""
duplicate_finder.py — Detect and move duplicate files recursively.

A file is considered a duplicate if another file with the same extension
and the same content hash has already been seen during the scan.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import shutil
import sys
from pathlib import Path


CHUNK_SIZE = 8192  # 8 KB read chunks


def compute_hash(file_path: Path, algorithm: str) -> str | None:
    """Return the hex digest of a file's content, or None on error."""
    h = hashlib.new(algorithm)
    try:
        with file_path.open("rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as exc:
        print(f"  [WARN] Cannot read {file_path}: {exc}", file=sys.stderr)
        return None


def safe_destination(output_dir: Path, filename: str) -> Path:
    """Return a collision-free destination path inside output_dir."""
    dest = output_dir / filename
    if not dest.exists():
        return dest
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    counter = 1
    while True:
        dest = output_dir / f"{stem}_{counter}{suffix}"
        if not dest.exists():
            return dest
        counter += 1


def find_and_move_duplicates(
    source_dir: Path,
    output_dir: Path,
    algorithm: str,
    dry_run: bool,
    filter_exts: set[str] | None = None,
    timestamp: str = "",
    preview_file: bool = False,
) -> tuple[int, int]:
    """
    Scan source_dir recursively for duplicates.

    filter_exts:  if provided, only files whose lowercased extension is in this
                  set are considered (e.g. {'.pdf', '.doc'}).
    preview_file: when True and dry_run is True, write a preview report file to
                  output_dir in addition to printing the preview to stdout.

    Returns (total_scanned, total_duplicates).
    """
    # key: (hash, extension_lower) -> original Path
    seen: dict[tuple[str, str], Path] = {}
    report: dict[Path, list[Path]] = {}  # original -> list of duplicates
    total_scanned = 0
    total_duplicates = 0

    output_dir_resolved = output_dir.resolve()

    print(f"Scanning: {source_dir.resolve()}")
    print(f"Output  : {output_dir_resolved}")
    ext_display = ", ".join(sorted(filter_exts)) if filter_exts else "all"
    print(f"Algorithm: {algorithm.upper()}  |  Dry-run: {dry_run}  |  Extensions: {ext_display}\n")

    for file_path in sorted(source_dir.rglob("*")):
        # Skip directories and anything inside the output folder
        if not file_path.is_file():
            continue
        if file_path.resolve().is_relative_to(output_dir_resolved):
            continue

        # Apply extension filter
        if filter_exts is not None and file_path.suffix.lower() not in filter_exts:
            continue

        total_scanned += 1
        ext = file_path.suffix.lower()
        file_hash = compute_hash(file_path, algorithm)
        if file_hash is None:
            continue

        key = (file_hash, ext)

        if key in seen:
            original = seen[key]
            total_duplicates += 1
            dest_name = file_path.name
            dest_path = safe_destination(output_dir_resolved, dest_name)

            report.setdefault(original.resolve(), []).append(file_path.resolve())

            if dry_run:
                print(f"[DRY-RUN] Would move: {file_path.resolve()}")
                print(f"          -> {dest_path}")
                print(f"          Original : {original.resolve()}\n")
            else:
                output_dir_resolved.mkdir(parents=True, exist_ok=True)
                shutil.move(str(file_path), str(dest_path))
                print(f"Moved   : {file_path.name}")
                print(f"  -> {dest_path}")
                print(f"  Original: {original.resolve()}\n")
        else:
            seen[key] = file_path

    # Write report
    if report:
        report_lines = [
            f"ORIGINAL: {orig}  |  DUPLICATE: {', '.join(str(d) for d in dups)}"
            for orig, dups in report.items()
        ]
        if dry_run:
            if preview_file:
                report_path = output_dir_resolved / f"duplicates_report_preview_{timestamp}.txt"
                output_dir_resolved.mkdir(parents=True, exist_ok=True)
                report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
                print(f"[DRY-RUN] Preview report written to: {report_path}")
            print("\n--- Report preview ---")
            for line in report_lines:
                print(line)
        else:
            report_path = output_dir_resolved / f"duplicates_report_{timestamp}.txt"
            output_dir_resolved.mkdir(parents=True, exist_ok=True)
            report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
            print(f"\nReport written: {report_path}")

    return total_scanned, total_duplicates


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect and move duplicate files in a directory tree.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan ~/Downloads, move duplicates to ~/duplicates/
  python duplicate_finder.py ~/Downloads --output-dir ~/duplicates

  # Preview without moving (dry-run)
  python duplicate_finder.py ~/Downloads --output-dir ~/duplicates --dry-run

  # Use faster MD5 hashing
  python duplicate_finder.py ~/Documents --output-dir ./dupes --hash-algo md5
""",
    )
    parser.add_argument(
        "source_dir",
        type=Path,
        help="Directory to scan recursively for duplicates",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./duplicates"),
        metavar="DIR",
        help="Destination folder for duplicates and report (default: ./duplicates)",
    )
    parser.add_argument(
        "--hash-algo",
        choices=["md5", "sha256", "sha1"],
        default="sha256",
        metavar="ALGO",
        help="Hash algorithm: md5, sha1, sha256 (default: sha256)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without moving any files",
    )
    parser.add_argument(
        "--filter-ext",
        nargs="+",
        metavar="EXT",
        default=None,
        help="Only scan files with these extensions, e.g. --filter-ext .pdf .doc .txt",
    )
    parser.add_argument(
        "--preview-file",
        action="store_true",
        help="Write a preview report file when using --dry-run (named duplicates_report_preview_<timestamp>.txt)",
    )
    args = parser.parse_args()

    source_dir: Path = args.source_dir.expanduser().resolve()
    output_dir: Path = args.output_dir.expanduser().resolve()

    if not source_dir.is_dir():
        parser.error(f"Source directory does not exist: {source_dir}")

    filter_exts: set[str] | None = None
    if args.filter_ext:
        filter_exts = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in args.filter_ext}

    timestamp = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")

    scanned, duplicates = find_and_move_duplicates(
        source_dir, output_dir, args.hash_algo, args.dry_run, filter_exts, timestamp,
        args.preview_file,
    )

    print("\n" + "=" * 50)
    print(f"Files scanned : {scanned}")
    print(f"Duplicates    : {duplicates}")
    if not args.dry_run and duplicates:
        print(f"Moved to      : {output_dir}")
    print("=" * 50)


if __name__ == "__main__":
    main()
