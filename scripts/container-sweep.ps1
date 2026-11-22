<#
.SYNOPSIS
  Windows counterpart of container-sweep.sh: run the language runtimes and
  databases laboon is expected to handle, each as an OCI image, and report which
  start and execute. A version command per image starts the full runtime and
  exits; it is not a full test suite.

.PARAMETER Laboon
  The laboon.exe to use (default: .\laboon.exe).

.NOTES
  Env: PLATFORM (linux/amd64|linux/arm64), SWEEP_NET (any value -> pass -net).
  laboon is invoked through `cmd /c` with cmd-level redirection: PowerShell's own
  native-stream redirection deadlocks a child that writes to its console.
  Exit code is the number of non-deferred images that failed.
#>
param([string]$Laboon = ".\laboon.exe")

$ErrorActionPreference = "Continue"
$plat = if ($env:PLATFORM) { "-platform $($env:PLATFORM) " } else { "" }
$net  = if ($env:SWEEP_NET) { "-net " } else { "" }

$pass = 0; $fail = 0; $fails = @()

# Run NAME MARKER IMAGE CMD...: run IMAGE's CMD under laboon, expect MARKER in
# the output. A leading "?" on NAME marks a known-deferred image. The command
# must be quote-free so the single cmd string needs no escaping. A failure's
# whole output is kept in sweep-fail-NAME.txt.
function Run([string]$name, [string]$marker, [string]$image) {
    $cmd = $args -join " "
    $defer = $false
    if ($name.StartsWith("?")) { $defer = $true; $name = $name.Substring(1) }
    $line = "$Laboon $plat$net-image $image $cmd"
    # Redirect at the cmd level to a file, then read it: piping a native child's
    # output straight into PowerShell (| Out-String) can deadlock it.
    $tmp = [System.IO.Path]::GetTempFileName()
    cmd /c "$line > `"$tmp`" 2>&1"
    $rc = $LASTEXITCODE
    $out = (Get-Content $tmp -Raw -ErrorAction SilentlyContinue)
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($null -eq $out) { $out = "" }
    if ($rc -eq 0 -and $out -match [regex]::Escape($marker)) {
        Write-Output "PASS  $name ($image)"
        $script:pass++
    } elseif ($defer) {
        Write-Output "DEFER $name ($image): rc=$rc (known)"
    } else {
        $last = ($out -split "`n" | Where-Object { $_ -ne "" } | Select-Object -Last 1)
        Write-Output ("FAIL  {0} ({1}): rc={2} | {3}" -f $name, $image, $rc, $last)
        Set-Content "sweep-fail-$name.txt" $out
        $script:fail++; $script:fails += $name
    }
}

Write-Output "== container sweep: $Laboon $($env:PLATFORM) $(Get-Date)"

Run python  Python   python:3.12-alpine        python3 --version
Run node    v22      node:22-alpine            node --version
Run ruby    ruby     ruby:3.3-alpine           ruby --version
Run perl    perl     perl:5.40                 perl --version
Run php     PHP      php:8.3-cli-alpine        php --version
Run go      go       golang:1.23-alpine        go version
Run rust    rustc    rust:1.82-alpine          rustc --version
Run java    version  eclipse-temurin:21        java -version
Run gcc     gcc      gcc:14                     gcc --version
Run busybox Linux    busybox:1.36              busybox uname -s
Run redis    Redis    redis:7-alpine           redis-server --version
Run postgres postgres postgres:16-alpine       postgres --version
Run mariadb  mariadb  mariadb:11               mariadbd --version
Run dotnet    dotnet  mcr.microsoft.com/dotnet/runtime:8.0  dotnet --info

Write-Output "== sweep done: $pass passed, $fail failed $(if ($fails) { '(' + ($fails -join ' ') + ')' })"
exit $fail
