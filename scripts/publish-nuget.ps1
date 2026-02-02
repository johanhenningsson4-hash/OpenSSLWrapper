<#
.SYNOPSIS
    Build, pack and publish the OpenSLLWrapper NuGet package to nuget.org.

.DESCRIPTION
    This script builds the `OpenSLLWrapper` project in Release configuration, packs a NuGet package
    from the project file and pushes it to nuget.org using an API key.

.PARAMETER ApiKey
    NuGet API key. If not provided, the script will use the `NUGET_API_KEY` environment variable.

.PARAMETER Version
    Package version to use for the nupkg. If not provided, the script will attempt to read
    the version from `OpenSLLWrapper/Properties/AssemblyInfo.cs` (AssemblyFileVersion or AssemblyVersion).

.EXAMPLE
    .\publish-nuget.ps1 -ApiKey xxxxx -Version 1.0.1

    Uses the provided API key and version to create a package and push it to nuget.org.
#>

param(
    [string]$ApiKey = $env:NUGET_API_KEY,
    [string]$Version = ''
)

# Resolve repository root and ensure paths work regardless of current working directory
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$root = Resolve-Path (Join-Path $scriptRoot '..')


function Fail([string]$msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# Ensure API key
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Fail "No NuGet API key provided. Set the NUGET_API_KEY environment variable or pass -ApiKey."
}

$projPath = Join-Path $root "OpenSLLWrapper\OpenSLLWrapper.csproj"
if (-not (Test-Path $projPath)) {
    Fail "Project file not found: $projPath"
}

# Try to infer version from AssemblyInfo if not provided
if ([string]::IsNullOrWhiteSpace($Version)) {
    $asmInfo = Join-Path $root "OpenSLLWrapper\Properties\AssemblyInfo.cs"
    if (Test-Path $asmInfo) {
        $content = Get-Content $asmInfo -Raw
        $m = [regex]::Match($content, 'AssemblyFileVersion\("(?<v>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"\)')
        if ($m.Success) {
            $Version = $m.Groups['v'].Value
            Write-Host "Using version from AssemblyFileVersion: $Version"
        } else {
            $m2 = [regex]::Match($content, 'AssemblyVersion\("(?<v>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"\)')
            if ($m2.Success) { $Version = $m2.Groups['v'].Value; Write-Host "Using version from AssemblyVersion: $Version" }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    Fail "Package version not provided and could not be inferred. Provide -Version or set AssemblyFileVersion."
}

# Ensure artifacts directory
$artifacts = Join-Path -Path $root -ChildPath "artifacts"
if (-not (Test-Path $artifacts)) { New-Item -ItemType Directory -Path $artifacts | Out-Null }

# Ensure nuget.exe exists (download if missing)
$toolsDir = Join-Path $root '.tools'
if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir | Out-Null }
$nugetExe = Join-Path $toolsDir 'nuget.exe'
if (-not (Test-Path $nugetExe)) {
    Write-Host "nuget.exe not found. Downloading latest nuget.exe to $nugetExe ..."
    $nugetUrl = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
    try {
        Invoke-WebRequest -Uri $nugetUrl -OutFile $nugetExe -UseBasicParsing
    } catch {
        Fail "Failed to download nuget.exe: $_"
    }
}

# Build project (Release)
Write-Host "Building project in Release configuration..."
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    & dotnet build $projPath -c Release
} else {
    & msbuild $projPath /t:Build /p:Configuration=Release
}
if ($LASTEXITCODE -ne 0) { Fail "MSBuild failed with exit code $LASTEXITCODE" }

# Pack using nuget.exe (prefer .nuspec if present so README/icon are included)
Write-Host "Packing nupkg (version: $Version) ..."
$nuspecPath = Join-Path (Join-Path $root 'OpenSLLWrapper') 'OpenSLLWrapper.nuspec'
if (Test-Path $nuspecPath) {
    Write-Host "Found nuspec: $nuspecPath - using nuspec to pack (includes README/icon)"
    $packArgs = @('pack', $nuspecPath, '-Version', $Version, '-OutputDirectory', $artifacts)
} else {
    $packArgs = @('pack', $projPath, '-Properties', "Configuration=Release", '-Version', $Version, '-OutputDirectory', $artifacts, '-IncludeReferencedProjects')
}

$packResult = & $nugetExe @packArgs
if ($LASTEXITCODE -ne 0) { Fail "nuget pack failed with exit code $LASTEXITCODE`n$packResult" }

# Find the produced nupkg
$nupkgs = Get-ChildItem -Path $artifacts -Filter "*.nupkg" | Sort-Object LastWriteTime -Descending
if ($nupkgs.Count -eq 0) { Fail "No nupkg found in $artifacts" }
# Prefer matching package id
$nupkg = $nupkgs | Where-Object { $_.Name -like "OpenSLLWrapper*$Version*.nupkg" } | Select-Object -First 1
if (-not $nupkg) { $nupkg = $nupkgs[0] }

Write-Host "Found package: $($nupkg.FullName)"

# Push to nuget.org
Write-Host "Pushing package to nuget.org..."
$pushArgs = @('push', $nupkg.FullName, $ApiKey, '-Source', 'https://api.nuget.org/v3/index.json')
$pushResult = & $nugetExe @pushArgs
if ($LASTEXITCODE -ne 0) { Fail "nuget push failed with exit code $LASTEXITCODE`n$pushResult" }

Write-Host "Package pushed successfully." -ForegroundColor Green
exit 0
