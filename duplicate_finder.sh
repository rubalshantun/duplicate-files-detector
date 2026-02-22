#!/usr/bin/env bash
# =============================================================================
# duplicate_finder.sh — detect and move duplicate files recursively
#
# A file is a duplicate when another file with the same extension AND the same
# content hash has already been seen during the scan. The first occurrence is
# kept as the original; every subsequent match is moved to the output directory.
#
# Requirements:
#   - bash 4.2+  (associative arrays + [[ -v key ]] test + ${var^^} case ops)
#   - find, sort, mv, mkdir  (POSIX / GNU coreutils — standard on any Linux)
#   - one of: sha256sum / shasum  (SHA-256)
#             sha1sum  / shasum  (SHA-1)
#             md5sum   / md5     (MD5)
#
# Linux : sha256sum, sha1sum, md5sum are part of GNU coreutils (always present)
# macOS : install bash 4+ via Homebrew (brew install bash) then invoke with
#         the full path, e.g. /usr/local/bin/bash duplicate_finder.sh ...
# =============================================================================

set -uo pipefail

# -----------------------------------------------------------------------------
# Minimum bash version check (4.2 required for declare -A and [[ -v ]])
# -----------------------------------------------------------------------------
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]] || \
   { [[ "${BASH_VERSINFO[0]}" -eq 4 ]] && [[ "${BASH_VERSINFO[1]}" -lt 2 ]]; }; then
    echo "Error: bash 4.2 or newer is required (found: $BASH_VERSION)" >&2
    echo "Linux systems ship with bash 4+ by default." >&2
    echo "On macOS: brew install bash, then use: /usr/local/bin/bash $0 ..." >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage:
  duplicate_finder.sh <source_dir> [options]

Options:
  --output-dir DIR            Destination for duplicates and report
                              (default: ./duplicates)
  --hash-algo ALGO            md5 | sha1 | sha256  (default: sha256)
  --dry-run                   Preview actions without moving any files
  --preview-file              Write a preview report file when using --dry-run;
                              has no effect without --dry-run
  --filter-ext EXT [EXT ...]  Only scan files with these extensions
                              (leading dot optional, e.g. .pdf .doc  or  pdf doc)
  -h, --help                  Show this help

Examples:
  ./duplicate_finder.sh ~/Downloads
  ./duplicate_finder.sh ~/Downloads --output-dir ~/dupes --dry-run
  ./duplicate_finder.sh ~/Downloads --output-dir ~/dupes --dry-run --preview-file
  ./duplicate_finder.sh ~/Downloads --hash-algo md5
  ./duplicate_finder.sh ~/Documents --filter-ext .pdf .doc .docx
  ./duplicate_finder.sh ~/Photos    --filter-ext .jpg .png --dry-run
EOF
}

# -----------------------------------------------------------------------------
# Helper: resolve an absolute path, works even if the path does not yet exist.
# Resolves symlinks for existing components; appends non-existent tail as-is.
# -----------------------------------------------------------------------------
get_realpath() {
    local path="$1"
    if [[ -e "$path" ]]; then
        if command -v realpath &>/dev/null; then
            realpath "$path"
        elif command -v readlink &>/dev/null; then
            readlink -f "$path"
        else
            # pure-bash fallback (no symlink resolution)
            [[ "$path" != /* ]] && path="$PWD/$path"
            echo "$path"
        fi
    else
        # Path does not exist yet — resolve the nearest existing ancestor,
        # then append the remaining components.
        local parent basename
        basename=$(basename "$path")
        parent=$(dirname  "$path")
        parent=$(get_realpath "$parent")
        echo "$parent/$basename"
    fi
}

# -----------------------------------------------------------------------------
# Helper: return 0 if $1 is inside (or equal to) directory $2
# -----------------------------------------------------------------------------
is_descendant() {
    local child="$1" parent="$2"
    case "$child" in
        "$parent"/*|"$parent") return 0 ;;
        *) return 1 ;;
    esac
}

# -----------------------------------------------------------------------------
# Helper: print the lowercased extension with leading dot, or "" if none.
#   Matches Python's Path.suffix behaviour:
#     "file.txt"    ->  ".txt"
#     ".hidden"     ->  ""
#     "file.tar.gz" ->  ".gz"
# -----------------------------------------------------------------------------
get_extension() {
    local filename="$1"
    local bare="${filename#.}"          # strip one leading dot (handles .hidden)
    if [[ "$bare" == *.* ]]; then
        local raw="${filename##*.}"     # everything after the last dot
        echo ".${raw,,}"               # lowercase with leading dot
    else
        echo ""
    fi
}

# -----------------------------------------------------------------------------
# Helper: compute file hash; prints the hex digest or "" on error
# -----------------------------------------------------------------------------
compute_hash() {
    local file="$1" algo="$2"
    local digest=""
    case "$algo" in
        sha256)
            if   command -v sha256sum &>/dev/null; then
                digest=$(sha256sum     "$file" 2>/dev/null | awk '{print $1}')
            elif command -v shasum    &>/dev/null; then
                digest=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
            fi ;;
        sha1)
            if   command -v sha1sum &>/dev/null; then
                digest=$(sha1sum       "$file" 2>/dev/null | awk '{print $1}')
            elif command -v shasum  &>/dev/null; then
                digest=$(shasum -a 1   "$file" 2>/dev/null | awk '{print $1}')
            fi ;;
        md5)
            if   command -v md5sum &>/dev/null; then
                digest=$(md5sum        "$file" 2>/dev/null | awk '{print $1}')
            elif command -v md5    &>/dev/null; then
                digest=$(md5 -q        "$file" 2>/dev/null)
            fi ;;
    esac
    if [[ -z "$digest" ]]; then
        echo "  [WARN] Cannot read or hash: $file" >&2
    fi
    echo "$digest"
}

# -----------------------------------------------------------------------------
# Helper: print a collision-free destination path inside $dir for $filename
# -----------------------------------------------------------------------------
get_safe_destination() {
    local dir="$1" filename="$2"
    local dest="$dir/$filename"
    [[ ! -e "$dest" ]] && { echo "$dest"; return; }

    local stem ext n=1
    if [[ "$filename" == *.* ]]; then
        ext=".${filename##*.}"
        stem="${filename%.*}"
    else
        ext=""
        stem="$filename"
    fi

    while true; do
        dest="$dir/${stem}_${n}${ext}"
        [[ ! -e "$dest" ]] && { echo "$dest"; return; }
        n=$((n + 1))
    done
}

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
source_dir=""
output_dir="./duplicates"
hash_algo="sha256"
dry_run=false
preview_file=false
declare -a filter_exts=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage; exit 0 ;;

        --output-dir)
            [[ $# -lt 2 ]] && { echo "Error: --output-dir requires a value" >&2; exit 1; }
            output_dir="$2"; shift 2 ;;

        --hash-algo)
            [[ $# -lt 2 ]] && { echo "Error: --hash-algo requires a value" >&2; exit 1; }
            hash_algo="${2,,}"
            case "$hash_algo" in
                md5|sha1|sha256) ;;
                *) echo "Error: --hash-algo must be md5, sha1, or sha256" >&2; exit 1 ;;
            esac
            shift 2 ;;

        --dry-run)
            dry_run=true; shift ;;

        --preview-file)
            preview_file=true; shift ;;

        --filter-ext)
            shift
            while [[ $# -gt 0 ]] && [[ "$1" != --* ]] && [[ "$1" != -h ]]; do
                local_ext="${1,,}"
                [[ "$local_ext" != .* ]] && local_ext=".$local_ext"
                filter_exts+=("$local_ext")
                shift
            done
            [[ ${#filter_exts[@]} -eq 0 ]] && {
                echo "Error: --filter-ext requires at least one extension" >&2; exit 1
            } ;;

        --*)
            echo "Error: Unknown option: $1" >&2; usage >&2; exit 1 ;;

        *)
            if [[ -z "$source_dir" ]]; then
                source_dir="$1"
            else
                echo "Error: Unexpected argument: $1" >&2; usage >&2; exit 1
            fi
            shift ;;
    esac
done

if [[ -z "$source_dir" ]]; then
    echo "Error: source_dir is required" >&2; usage >&2; exit 1
fi
if [[ ! -d "$source_dir" ]]; then
    echo "Error: Source directory does not exist: $source_dir" >&2; exit 1
fi

source_dir=$(get_realpath "$source_dir")
output_dir=$(get_realpath "$output_dir")

# -----------------------------------------------------------------------------
# Timestamp (captured once so the report filename is consistent for the run)
# -----------------------------------------------------------------------------
timestamp=$(date +%Y_%m_%d_%H_%M_%S)

# -----------------------------------------------------------------------------
# Header
# -----------------------------------------------------------------------------
if [[ ${#filter_exts[@]} -gt 0 ]]; then
    mapfile -t sorted_exts < <(printf '%s\n' "${filter_exts[@]}" | sort)
    ext_display="${sorted_exts[0]}"
    for e in "${sorted_exts[@]:1}"; do ext_display+=", $e"; done
else
    ext_display="all"
fi

echo "Scanning: $source_dir"
echo "Output  : $output_dir"
echo "Algorithm: ${hash_algo^^}  |  Dry-run: $dry_run  |  Extensions: $ext_display"
echo ""

# -----------------------------------------------------------------------------
# Main scan
# -----------------------------------------------------------------------------
declare -A seen=()          # "$hash|$ext"  ->  original full path
declare -a report_origs=()  # original paths in insertion order
declare -a report_dups=()   # CSV of dup paths, parallel to report_origs
declare -A orig_idx=()      # original path -> index in report_origs

total_scanned=0
total_duplicates=0

while IFS= read -r -d $'\0' file; do

    # Skip anything inside the output folder
    is_descendant "$file" "$output_dir" && continue

    filename=$(basename "$file")
    ext=$(get_extension "$filename")

    # Apply extension filter
    if [[ ${#filter_exts[@]} -gt 0 ]]; then
        match=false
        for fe in "${filter_exts[@]}"; do
            [[ "$ext" == "$fe" ]] && { match=true; break; }
        done
        $match || continue
    fi

    total_scanned=$((total_scanned + 1))

    hash=$(compute_hash "$file" "$hash_algo")
    [[ -z "$hash" ]] && continue

    key="${hash}|${ext}"

    if [[ -v seen["$key"] ]]; then
        original="${seen[$key]}"
        total_duplicates=$((total_duplicates + 1))
        dest_path=$(get_safe_destination "$output_dir" "$filename")

        # Accumulate for report (group duplicates under their original)
        if [[ -v orig_idx["$original"] ]]; then
            idx="${orig_idx[$original]}"
            report_dups[$idx]="${report_dups[$idx]}, $file"
        else
            idx=${#report_origs[@]}
            report_origs+=("$original")
            report_dups+=("$file")
            orig_idx["$original"]=$idx
        fi

        if $dry_run; then
            echo "[DRY-RUN] Would move: $file"
            echo "          -> $dest_path"
            echo "          Original : $original"
            echo ""
        else
            mkdir -p "$output_dir"
            mv "$file" "$dest_path"
            echo "Moved   : $filename"
            echo "  -> $dest_path"
            echo "  Original: $original"
            echo ""
        fi
    else
        seen["$key"]="$file"
    fi

done < <(find "$source_dir" -type f -print0 | sort -z)

# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------
if [[ ${#report_origs[@]} -gt 0 ]]; then
    declare -a report_lines=()
    for i in "${!report_origs[@]}"; do
        report_lines+=("ORIGINAL: ${report_origs[$i]}  |  DUPLICATE: ${report_dups[$i]}")
    done

    if $dry_run; then
        if $preview_file; then
            report_path="$output_dir/duplicates_report_preview_$timestamp.txt"
            mkdir -p "$output_dir"
            printf '%s\n' "${report_lines[@]}" > "$report_path"
            echo "[DRY-RUN] Preview report written to: $report_path"
        fi
        echo ""
        echo "--- Report preview ---"
        printf '%s\n' "${report_lines[@]}"
    else
        report_path="$output_dir/duplicates_report_$timestamp.txt"
        mkdir -p "$output_dir"
        printf '%s\n' "${report_lines[@]}" > "$report_path"
        echo ""
        echo "Report written: $report_path"
    fi
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
printf '=%.0s' {1..50}; echo ""
echo "Files scanned : $total_scanned"
echo "Duplicates    : $total_duplicates"
if ! $dry_run && [[ $total_duplicates -gt 0 ]]; then
    echo "Moved to      : $output_dir"
fi
printf '=%.0s' {1..50}; echo ""