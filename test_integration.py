#!/usr/bin/env python3
"""
Integration tests for duplicate_finder.py.

Each test builds a tmp directory tree, runs duplicate_finder.py as a
subprocess, verifies stdout / filesystem state, then cleans up.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent / "duplicate_finder.py"
PYTHON = sys.executable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, str(SCRIPT)] + args,
        capture_output=True,
        text=True,
    )


def make_tree(base: Path, files: dict[str, bytes]) -> None:
    """Create files under base. Keys are relative paths, values are content."""
    for rel, content in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)


# ---------------------------------------------------------------------------
# Test 1: dry-run — no files moved, stdout contains expected markers
# ---------------------------------------------------------------------------

def test_dry_run_no_files_moved() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.txt": b"hello",
            "sub/b.txt": b"hello",   # duplicate of a.txt
            "c.txt": b"world",        # unique
        })

        result = run([str(src), "--output-dir", str(out), "--dry-run"])

        assert result.returncode == 0, result.stderr

        # Output dir must NOT be created during dry-run
        assert not out.exists(), "dry-run must not create the output directory"

        # Original files must all still be present
        assert (src / "a.txt").exists()
        assert (src / "sub" / "b.txt").exists()
        assert (src / "c.txt").exists()

        # stdout must mention the duplicate with full paths
        assert "[DRY-RUN] Would move:" in result.stdout
        assert str((src / "sub" / "b.txt").resolve()) in result.stdout
        assert str((src / "a.txt").resolve()) in result.stdout

        # Report preview section must appear
        assert "--- Report preview ---" in result.stdout
        assert "ORIGINAL:" in result.stdout
        assert "DUPLICATE:" in result.stdout

        print("PASS test_dry_run_no_files_moved")


# ---------------------------------------------------------------------------
# Test 2: dry-run report format — ORIGINAL left, DUPLICATE CSV right
# ---------------------------------------------------------------------------

def test_dry_run_report_format() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        content = b"same content"
        make_tree(src, {
            "orig.txt": content,
            "dup1.txt": content,
            "nested/dup2.txt": content,
        })

        result = run([str(src), "--output-dir", str(out), "--dry-run"])

        assert result.returncode == 0, result.stderr

        # Find the report lines (after "--- Report preview ---")
        preview_start = result.stdout.index("--- Report preview ---")
        preview_section = result.stdout[preview_start:]

        # Each report line must start with ORIGINAL: and contain DUPLICATE:
        report_lines = [
            l for l in preview_section.splitlines()
            if l.startswith("ORIGINAL:")
        ]
        assert len(report_lines) == 1, f"Expected 1 original, got: {report_lines}"

        line = report_lines[0]
        orig_part, dup_part = line.split("  |  DUPLICATE:")
        assert orig_part.startswith("ORIGINAL:")

        # Full path of original must be present
        orig_path = orig_part.replace("ORIGINAL:", "").strip()
        assert Path(orig_path).is_absolute(), f"ORIGINAL path not absolute: {orig_path}"

        # Both duplicates must appear as CSV on the right
        dup_paths = [p.strip() for p in dup_part.split(",")]
        assert len(dup_paths) == 2, f"Expected 2 duplicate paths, got: {dup_paths}"
        for dp in dup_paths:
            assert Path(dp).is_absolute(), f"DUPLICATE path not absolute: {dp}"

        print("PASS test_dry_run_report_format")


# ---------------------------------------------------------------------------
# Test 3: actual move — duplicates relocated, originals intact, report written
# ---------------------------------------------------------------------------

def test_actual_move() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        # Name files so alphabetical order is deterministic: a_ sorts before b_
        make_tree(src, {
            "a_original.jpg": b"image bytes",
            "b_copy.jpg": b"image bytes",   # duplicate — sorts after, will be moved
            "unique.jpg": b"other image",    # unique
        })

        result = run([str(src), "--output-dir", str(out)])

        assert result.returncode == 0, result.stderr

        # a_original (first seen) and unique must still be in src
        assert (src / "a_original.jpg").exists(), "original was incorrectly moved"
        assert (src / "unique.jpg").exists(), "unique file was incorrectly moved"

        # b_copy (duplicate) must have been moved out of src
        assert not (src / "b_copy.jpg").exists(), "duplicate was not moved"

        # output dir must contain exactly the one moved .jpg
        moved_files = list(out.glob("*.jpg"))
        assert len(moved_files) == 1, f"Expected 1 moved file, got {moved_files}"
        assert moved_files[0].read_bytes() == b"image bytes", "moved file content mismatch"

        # report file must exist with correct format
        report = out / "duplicates_report.txt"
        assert report.exists(), "report file missing"
        lines = report.read_text().splitlines()
        assert len(lines) == 1, f"Expected 1 report line, got {lines}"
        assert lines[0].startswith("ORIGINAL:"), f"bad report format: {lines[0]}"
        assert "  |  DUPLICATE:" in lines[0], f"missing DUPLICATE section: {lines[0]}"
        orig_path = lines[0].split("  |  DUPLICATE:")[0].replace("ORIGINAL:", "").strip()
        assert Path(orig_path).is_absolute(), f"ORIGINAL path not absolute: {orig_path}"

        print("PASS test_actual_move")


# ---------------------------------------------------------------------------
# Test 4: same name, different content — must NOT be treated as duplicate
# ---------------------------------------------------------------------------

def test_same_name_different_content_not_duplicate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "file.txt": b"content A",
            "sub/file.txt": b"content B",  # same name, different content
        })

        result = run([str(src), "--output-dir", str(out), "--dry-run"])

        assert result.returncode == 0, result.stderr
        assert "[DRY-RUN] Would move:" not in result.stdout
        assert "Duplicates    : 0" in result.stdout

        print("PASS test_same_name_different_content_not_duplicate")


# ---------------------------------------------------------------------------
# Test 5: different extension, same content — must NOT be treated as duplicate
# ---------------------------------------------------------------------------

def test_same_content_different_extension_not_duplicate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "file.txt": b"identical",
            "file.jpg": b"identical",  # same bytes, different ext
        })

        result = run([str(src), "--output-dir", str(out), "--dry-run"])

        assert result.returncode == 0, result.stderr
        assert "[DRY-RUN] Would move:" not in result.stdout
        assert "Duplicates    : 0" in result.stdout

        print("PASS test_same_content_different_extension_not_duplicate")


# ---------------------------------------------------------------------------
# Test 6: hash algorithm flag (md5 / sha1) — duplicates still detected
# ---------------------------------------------------------------------------

def test_hash_algo_md5() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.bin": b"data",
            "b.bin": b"data",
        })

        result = run([str(src), "--output-dir", str(out), "--hash-algo", "md5", "--dry-run"])

        assert result.returncode == 0, result.stderr
        assert "MD5" in result.stdout
        assert "Duplicates    : 1" in result.stdout

        print("PASS test_hash_algo_md5")


def test_hash_algo_sha1() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.bin": b"data",
            "b.bin": b"data",
        })

        result = run([str(src), "--output-dir", str(out), "--hash-algo", "sha1", "--dry-run"])

        assert result.returncode == 0, result.stderr
        assert "SHA1" in result.stdout
        assert "Duplicates    : 1" in result.stdout

        print("PASS test_hash_algo_sha1")


# ---------------------------------------------------------------------------
# Test 7: name collision in output dir — safe_destination renames correctly
# ---------------------------------------------------------------------------

def test_name_collision_in_output() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        # Three files with the same name and content in different subdirs
        make_tree(src, {
            "a/photo.jpg": b"img",
            "b/photo.jpg": b"img",
            "c/photo.jpg": b"img",
        })

        result = run([str(src), "--output-dir", str(out)])

        assert result.returncode == 0, result.stderr

        # Two duplicates should have been moved; names must not collide
        moved = sorted(out.glob("photo*.jpg"))
        assert len(moved) == 2, f"Expected 2 moved files, got {moved}"
        names = {f.name for f in moved}
        assert len(names) == 2, f"Name collision in output: {names}"

        print("PASS test_name_collision_in_output")


# ---------------------------------------------------------------------------
# Test 8: no duplicates — output dir not created, summary shows 0
# ---------------------------------------------------------------------------

def test_no_duplicates_no_output_dir() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.txt": b"aaa",
            "b.txt": b"bbb",
            "c.txt": b"ccc",
        })

        result = run([str(src), "--output-dir", str(out)])

        assert result.returncode == 0, result.stderr
        assert not out.exists(), "output dir should not be created when no duplicates found"
        assert "Duplicates    : 0" in result.stdout

        print("PASS test_no_duplicates_no_output_dir")


# ---------------------------------------------------------------------------
# Test 9: files inside output dir are not scanned as source files
# ---------------------------------------------------------------------------

def test_output_dir_inside_source_not_double_counted() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = src / "duplicates"   # output is INSIDE source

        make_tree(src, {
            "a.txt": b"hello",
            "b.txt": b"hello",
        })

        result = run([str(src), "--output-dir", str(out)])

        assert result.returncode == 0, result.stderr
        # Only one duplicate should be detected, not files inside output dir
        assert "Duplicates    : 1" in result.stdout

        print("PASS test_output_dir_inside_source_not_double_counted")


# ---------------------------------------------------------------------------
# Test 10: invalid source dir — non-zero exit
# ---------------------------------------------------------------------------

def test_invalid_source_dir_exits_nonzero() -> None:
    result = run(["/nonexistent/path/xyz", "--output-dir", "/tmp/out"])
    assert result.returncode != 0, "expected non-zero exit for missing source dir"
    print("PASS test_invalid_source_dir_exits_nonzero")


# ---------------------------------------------------------------------------
# Test 11: --filter-ext only scans matching extensions
# ---------------------------------------------------------------------------

def test_filter_ext_only_scans_matching() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.pdf": b"pdf content",
            "b.pdf": b"pdf content",   # duplicate of a.pdf
            "a.txt": b"txt content",
            "b.txt": b"txt content",   # duplicate of a.txt — but filtered out
        })

        result = run([str(src), "--output-dir", str(out), "--filter-ext", ".pdf", "--dry-run"])

        assert result.returncode == 0, result.stderr
        # Only 2 .pdf files scanned; .txt files ignored
        assert "Files scanned : 2" in result.stdout
        assert "Duplicates    : 1" in result.stdout
        # The detected duplicate must be the .pdf, not .txt
        assert ".pdf" in result.stdout
        assert "[DRY-RUN] Would move:" in result.stdout

        print("PASS test_filter_ext_only_scans_matching")


# ---------------------------------------------------------------------------
# Test 12: --filter-ext with no dot prefix normalised correctly
# ---------------------------------------------------------------------------

def test_filter_ext_without_leading_dot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.doc": b"doc bytes",
            "b.doc": b"doc bytes",
        })

        # Pass "doc" without a leading dot — should still work
        result = run([str(src), "--output-dir", str(out), "--filter-ext", "doc", "--dry-run"])

        assert result.returncode == 0, result.stderr
        assert "Duplicates    : 1" in result.stdout

        print("PASS test_filter_ext_without_leading_dot")


# ---------------------------------------------------------------------------
# Test 13: --filter-ext with multiple extensions
# ---------------------------------------------------------------------------

def test_filter_ext_multiple_extensions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.pdf": b"pdf",
            "b.pdf": b"pdf",      # duplicate
            "a.doc": b"doc",
            "b.doc": b"doc",      # duplicate
            "a.jpg": b"image",
            "b.jpg": b"image",    # duplicate — but .jpg not in filter
        })

        result = run([
            str(src), "--output-dir", str(out),
            "--filter-ext", ".pdf", ".doc",
            "--dry-run",
        ])

        assert result.returncode == 0, result.stderr
        # 4 files scanned (.pdf x2, .doc x2); .jpg ignored
        assert "Files scanned : 4" in result.stdout
        assert "Duplicates    : 2" in result.stdout

        print("PASS test_filter_ext_multiple_extensions")


# ---------------------------------------------------------------------------
# Test 14: --filter-ext with no matches — nothing scanned
# ---------------------------------------------------------------------------

def test_filter_ext_no_matching_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a.txt": b"hello",
            "b.txt": b"hello",
        })

        result = run([str(src), "--output-dir", str(out), "--filter-ext", ".pdf", "--dry-run"])

        assert result.returncode == 0, result.stderr
        assert "Files scanned : 0" in result.stdout
        assert "Duplicates    : 0" in result.stdout

        print("PASS test_filter_ext_no_matching_files")


# ---------------------------------------------------------------------------
# Test 15: --filter-ext actual move — only matching extension files moved
# ---------------------------------------------------------------------------

def test_filter_ext_actual_move() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        out = Path(tmp) / "out"

        make_tree(src, {
            "a_orig.pdf": b"pdf data",
            "b_copy.pdf": b"pdf data",   # duplicate, will be moved
            "a_orig.txt": b"txt data",
            "b_copy.txt": b"txt data",   # duplicate, but .txt not filtered → stays
        })

        result = run([str(src), "--output-dir", str(out), "--filter-ext", ".pdf"])

        assert result.returncode == 0, result.stderr

        # .pdf duplicate must be moved
        assert not (src / "b_copy.pdf").exists(), ".pdf duplicate was not moved"
        assert (src / "a_orig.pdf").exists(), ".pdf original was incorrectly moved"

        # .txt files must be untouched
        assert (src / "a_orig.txt").exists(), ".txt file should not have been moved"
        assert (src / "b_copy.txt").exists(), ".txt file should not have been moved"

        # Only one file in output dir
        moved = list(out.glob("*"))
        non_report = [f for f in moved if f.name != "duplicates_report.txt"]
        assert len(non_report) == 1, f"Expected 1 moved file, got {non_report}"

        print("PASS test_filter_ext_actual_move")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

TESTS = [
    test_dry_run_no_files_moved,
    test_dry_run_report_format,
    test_actual_move,
    test_same_name_different_content_not_duplicate,
    test_same_content_different_extension_not_duplicate,
    test_hash_algo_md5,
    test_hash_algo_sha1,
    test_name_collision_in_output,
    test_no_duplicates_no_output_dir,
    test_output_dir_inside_source_not_double_counted,
    test_invalid_source_dir_exits_nonzero,
    test_filter_ext_only_scans_matching,
    test_filter_ext_without_leading_dot,
    test_filter_ext_multiple_extensions,
    test_filter_ext_no_matching_files,
    test_filter_ext_actual_move,
]


if __name__ == "__main__":
    failed = []
    for test in TESTS:
        try:
            test()
        except Exception as exc:
            print(f"FAIL {test.__name__}: {exc}")
            failed.append(test.__name__)

    print(f"\n{len(TESTS) - len(failed)}/{len(TESTS)} tests passed")
    if failed:
        print("Failed:", ", ".join(failed))
        sys.exit(1)
