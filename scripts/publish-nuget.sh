#!/usr/bin/env bash
set -euo pipefail

# Build, pack and push OpenSLLWrapper package to nuget.org using dotnet/nuget.
# Usage: ./publish-nuget.sh <api-key> [version]

API_KEY="${1:-${NUGET_API_KEY:-}}"
VERSION="${2:-}
"

if [ -z "$API_KEY" ]; then
  echo "ERROR: No API key specified. Pass as first argument or set NUGET_API_KEY." >&2
  exit 1
fi

PROJ_PATH="OpenSLLWrapper/OpenSLLWrapper.csproj"
if [ ! -f "$PROJ_PATH" ]; then
  echo "ERROR: Project file not found: $PROJ_PATH" >&2
  exit 1
fi

ARTIFACTS_DIR="artifacts"
mkdir -p "$ARTIFACTS_DIR"

if [ -z "$VERSION" ]; then
  # Try to infer from AssemblyInfo
  if [ -f "OpenSLLWrapper/Properties/AssemblyInfo.cs" ]; then
    VERSION=$(grep -oP 'AssemblyFileVersion\("\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' OpenSLLWrapper/Properties/AssemblyInfo.cs || true)
    if [ -n "$VERSION" ]; then
      echo "Using version from AssemblyFileVersion: $VERSION"
    fi
  fi
fi

if [ -z "$VERSION" ]; then
  echo "ERROR: Version not provided and could not be inferred." >&2
  exit 1
fi

# Build using msbuild (Windows) or dotnet (if available)
if command -v dotnet >/dev/null 2>&1; then
  dotnet build "$PROJ_PATH" -c Release
else
  msbuild "$PROJ_PATH" /p:Configuration=Release
fi

# Pack with nuget.exe if available, else use dotnet pack
if command -v nuget >/dev/null 2>&1; then
  nuget pack "$PROJ_PATH" -Properties Configuration=Release -Version $VERSION -OutputDirectory "$ARTIFACTS_DIR"
else
  if command -v dotnet >/dev/null 2>&1; then
    dotnet pack "$PROJ_PATH" -c Release -o "$ARTIFACTS_DIR" /p:PackageVersion=$VERSION
  else
    echo "ERROR: Neither nuget nor dotnet CLI found to pack the project." >&2
    exit 1
  fi
fi

# Find nupkg
NUPKG="$(ls -1t "$ARTIFACTS_DIR"/*.nupkg 2>/dev/null | head -n1)"
if [ -z "$NUPKG" ]; then
  echo "ERROR: No nupkg found in $ARTIFACTS_DIR" >&2
  exit 1
fi

# Push
if command -v nuget >/dev/null 2>&1; then
  nuget push "$NUPKG" -ApiKey "$API_KEY" -Source https://api.nuget.org/v3/index.json
else
  dotnet nuget push "$NUPKG" -k "$API_KEY" -s https://api.nuget.org/v3/index.json
fi

echo "Package pushed: $NUPKG"