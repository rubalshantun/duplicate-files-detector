#Requires -Version 5.1
<#
.SYNOPSIS
    Detect and move duplicate files recursively.

.DESCRIPTION
    Scans a source directory recursively for duplicate files.
    A file is a duplicate if another file with the same extension AND the same
    content hash has already been encountered during the scan. The first
    occurrence is kept as the original; every subsequent match is treated as a
    duplicate and moved to the output directory.

    No third-party software required — uses only built-in PowerShell cmdlets.

.PARAMETER SourceDir
    Directory to scan recursively for duplicates.

.PARAMETER OutputDir
    Destination folder for moved duplicates and the report file.
    Default: .\duplicates

.PARAMETER HashAlgo
    Hashing algorithm: MD5, SHA1, or SHA256. Default: SHA256.

.PARAMETER DryRun
    Preview actions without moving any files. The report is printed to the
    console. Combine with -PreviewFile to also save it to disk.

.PARAMETER PreviewFile
    When used together with -DryRun, writes a preview report file named
    duplicates_report_preview_<timestamp>.txt to OutputDir.
    Has no effect without -DryRun.

.PARAMETER FilterExt
    Only scan files whose extension matches one of the supplied values.
    The leading dot is optional, e.g. -FilterExt .pdf .doc  OR  pdf doc

.EXAMPLE
    # Basic scan — move duplicates to .\duplicates\
    .\duplicate_finder.ps1 C:\Downloads

.EXAMPLE
    # Custom output folder
    .\duplicate_finder.ps1 C:\Documents -OutputDir C:\Dupes

.EXAMPLE
    # Preview only (nothing moved, report printed to console)
    .\duplicate_finder.ps1 C:\Downloads -OutputDir C:\Dupes -DryRun

.EXAMPLE
    # Preview and save preview report file
    .\duplicate_finder.ps1 C:\Downloads -OutputDir C:\Dupes -DryRun -PreviewFile

.EXAMPLE
    # Faster scan with MD5
    .\duplicate_finder.ps1 C:\Photos -OutputDir C:\Dupes -HashAlgo MD5

.EXAMPLE
    # Only look for duplicate PDFs and Word documents
    .\duplicate_finder.ps1 C:\Documents -OutputDir C:\Dupes -FilterExt .pdf .doc .docx

.EXAMPLE
    # Dry-run scoped to images only
    .\duplicate_finder.ps1 C:\Photos -OutputDir C:\Dupes -FilterExt .jpg .png -DryRun
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$SourceDir,

    [string]$OutputDir = '.\duplicates',

    [ValidateSet('MD5', 'SHA1', 'SHA256')]
    [string]$HashAlgo = 'SHA256',

    [switch]$DryRun,

    [switch]$PreviewFile,

    [string[]]$FilterExt = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helper: return a collision-free destination path inside $Dir
# ---------------------------------------------------------------------------
function Get-SafeDestination {
    param(
        [string]$Dir,
        [string]$FileName
    )
    $dest = Join-Path $Dir $FileName
    if (-not (Test-Path -LiteralPath $dest)) { return $dest }

    $stem = [IO.Path]::GetFileNameWithoutExtension($FileName)
    $ext  = [IO.Path]::GetExtension($FileName)
    $n    = 1
    do {
        $dest = Join-Path $Dir "${stem}_${n}${ext}"
        $n++
    } while (Test-Path -LiteralPath $dest)

    return $dest
}

# ---------------------------------------------------------------------------
# Helper: compute file hash, return $null on read error
# ---------------------------------------------------------------------------
function Get-FileHashSafe {
    param(
        [string]$FilePath,
        [string]$Algorithm
    )
    try {
        return (Get-FileHash -LiteralPath $FilePath -Algorithm $Algorithm -ErrorAction Stop).Hash
    } catch {
        Write-Warning "Cannot read ${FilePath}: $_"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Helper: test whether $Child is inside (or equal to) $Parent (case-insensitive)
# ---------------------------------------------------------------------------
function Test-IsDescendant {
    param(
        [string]$Child,
        [string]$Parent
    )
    $sep = [IO.Path]::DirectorySeparatorChar
    $c   = [IO.Path]::GetFullPath($Child).TrimEnd($sep)
    $p   = [IO.Path]::GetFullPath($Parent).TrimEnd($sep)
    return $c.StartsWith($p + $sep, [StringComparison]::OrdinalIgnoreCase) -or
           [string]::Equals($c, $p, [StringComparison]::OrdinalIgnoreCase)
}

# ---------------------------------------------------------------------------
# Resolve and validate paths
# ---------------------------------------------------------------------------
$SourceDir = [IO.Path]::GetFullPath($SourceDir)
if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
    Write-Error "Source directory does not exist: $SourceDir"
    exit 1
}

$OutputDir = [IO.Path]::GetFullPath($OutputDir)

# ---------------------------------------------------------------------------
# Normalise extension filter — ensure every entry has a leading dot
# ---------------------------------------------------------------------------
$filterSet = $null
if ($null -ne $FilterExt -and $FilterExt.Count -gt 0) {
    $filterSet = $FilterExt | ForEach-Object {
        $e = $_.ToLower().Trim()
        if (-not $e.StartsWith('.')) { ".$e" } else { $e }
    }
}

# ---------------------------------------------------------------------------
# Capture timestamp once for consistent filenames
# ---------------------------------------------------------------------------
$timestamp = Get-Date -Format 'yyyy_MM_dd_HH_mm_ss'

# ---------------------------------------------------------------------------
# Print header
# ---------------------------------------------------------------------------
$extDisplay = if ($filterSet) { ($filterSet | Sort-Object) -join ', ' } else { 'all' }
Write-Host "Scanning: $SourceDir"
Write-Host "Output  : $OutputDir"
Write-Host "Algorithm: $($HashAlgo.ToUpper())  |  Dry-run: $($DryRun.IsPresent)  |  Extensions: $extDisplay"
Write-Host ''

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
$seen    = @{}          # "$hash|$ext"  ->  original full path (string)
$report  = [ordered]@{} # original path ->  List[string] of duplicate paths

$totalScanned    = 0
$totalDuplicates = 0

$allFiles = Get-ChildItem -LiteralPath $SourceDir -Recurse -File |
            Sort-Object FullName

foreach ($file in $allFiles) {
    $fullPath = $file.FullName

    # Skip anything inside the output folder
    if (Test-IsDescendant -Child $fullPath -Parent $OutputDir) { continue }

    # Apply extension filter
    $ext = $file.Extension.ToLower()
    if ($null -ne $filterSet -and $filterSet -notcontains $ext) { continue }

    $totalScanned++

    $hash = Get-FileHashSafe -FilePath $fullPath -Algorithm $HashAlgo
    if ($null -eq $hash) { continue }

    $key = "$hash|$ext"

    if ($seen.ContainsKey($key)) {
        $original = $seen[$key]
        $totalDuplicates++
        $destPath = Get-SafeDestination -Dir $OutputDir -FileName $file.Name

        # Accumulate for report
        if (-not $report.Contains($original)) {
            $report[$original] = [System.Collections.Generic.List[string]]::new()
        }
        $report[$original].Add($fullPath)

        if ($DryRun) {
            Write-Host "[DRY-RUN] Would move: $fullPath"
            Write-Host "          -> $destPath"
            Write-Host "          Original : $original"
            Write-Host ''
        } else {
            if (-not (Test-Path -LiteralPath $OutputDir)) {
                New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
            }
            Move-Item -LiteralPath $fullPath -Destination $destPath
            Write-Host "Moved   : $($file.Name)"
            Write-Host "  -> $destPath"
            Write-Host "  Original: $original"
            Write-Host ''
        }
    } else {
        $seen[$key] = $fullPath
    }
}

# ---------------------------------------------------------------------------
# Write / print report
# ---------------------------------------------------------------------------
if ($report.Count -gt 0) {
    $reportLines = @(
        foreach ($orig in $report.Keys) {
            $dups = @($report[$orig]) -join ', '
            "ORIGINAL: $orig  |  DUPLICATE: $dups"
        }
    )

    if ($DryRun) {
        if ($PreviewFile) {
            $reportPath = Join-Path $OutputDir "duplicates_report_preview_$timestamp.txt"
            if (-not (Test-Path -LiteralPath $OutputDir)) {
                New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
            }
            $reportLines | Set-Content -LiteralPath $reportPath -Encoding UTF8
            Write-Host "[DRY-RUN] Preview report written to: $reportPath"
        }
        Write-Host ''
        Write-Host '--- Report preview ---'
        $reportLines | ForEach-Object { Write-Host $_ }
    } else {
        $reportPath = Join-Path $OutputDir "duplicates_report_$timestamp.txt"
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        $reportLines | Set-Content -LiteralPath $reportPath -Encoding UTF8
        Write-Host ''
        Write-Host "Report written: $reportPath"
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 50)
Write-Host "Files scanned : $totalScanned"
Write-Host "Duplicates    : $totalDuplicates"
if (-not $DryRun -and $totalDuplicates -gt 0) {
    Write-Host "Moved to      : $OutputDir"
}
Write-Host ('=' * 50)