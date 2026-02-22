@echo off
:: ---------------------------------------------------------------------------
:: duplicate_finder.bat — thin launcher for duplicate_finder.ps1
::
:: Usage (from Command Prompt):
::   duplicate_finder.bat <SourceDir> [options]
::
:: Examples:
::   duplicate_finder.bat C:\Downloads
::   duplicate_finder.bat C:\Downloads -OutputDir C:\Dupes -DryRun
::   duplicate_finder.bat C:\Downloads -OutputDir C:\Dupes -DryRun -PreviewFile
::   duplicate_finder.bat C:\Downloads -FilterExt .pdf .doc
::   duplicate_finder.bat C:\Downloads -HashAlgo MD5
:: ---------------------------------------------------------------------------

:: Resolve the directory this .bat lives in so the .ps1 is always found
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%duplicate_finder.ps1"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*