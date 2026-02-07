# OpenSLLWrapper Development Guide

## Architecture Overview

OpenSLLWrapper is structured as a multi-targeted .NET library with comprehensive test coverage:

```
OpenSLLWrapper/
??? OpenSLLWrapper/              # Main library (multi-targeted: netstandard2.0, net472)
??? OpenSLLWrapper.UnitTests/    # Comprehensive unit tests (MSTest + FluentAssertions)
??? OpenSLLWrapper.Tests/        # Legacy integration/interoperability tests
??? BenchmarkSuite1/             # Performance benchmarks
```

## Development Requirements

### Prerequisites
- Visual Studio 2019/2022 or .NET SDK 6.0+
- .NET Framework 4.7.2 SDK (for full framework targeting)
- (Optional) OpenSSL CLI tools for interoperability testing

### Quick Setup
```bash
# Clone and restore packages
git clone <repository>
cd OpenSLLWrapper
dotnet restore

# Build the solution
dotnet build

# Run all tests
dotnet test OpenSLLWrapper.UnitTests/
```

## Multi-Targeting Strategy

The library targets:
- **netstandard2.0**: Broad compatibility with .NET Core, .NET 5+, and .NET Framework 4.6.1+
- **net472**: Full .NET Framework support with Windows-specific ACL operations

### Target Framework Considerations
```csharp
#if NET472
// Windows-specific ACL operations available
#endif
```

## Testing Strategy

### Unit Tests (`OpenSLLWrapper.UnitTests`)
- **Framework**: MSTest + FluentAssertions
- **Scope**: Individual method testing with mocking
- **Coverage**: All public APIs with edge cases and error conditions
- **Run**: `dotnet test OpenSLLWrapper.UnitTests/`

### Integration Tests (`OpenSLLWrapper.Tests`)
- **Framework**: Console application with manual assertions
- **Scope**: End-to-end scenarios and OpenSSL interoperability
- **Coverage**: Real cryptographic operations and file I/O
- **Run**: Build and execute the console application

### Test Categories
```csharp
[TestClass]
public class RsaKeyGenerationTests
{
    [TestMethod]
    public void GenerateRsaPrivateKeyBytes_ValidKeySize_ReturnsValidPem() { }
    
    [TestMethod]
    [DataRow(1024), DataRow(2048), DataRow(3072), DataRow(4096)]
    public void GenerateRsaPrivateKeyBytes_ValidKeySizes_ReturnsValidPem(int keySize) { }
    
    [TestMethod]
    public void GenerateRsaPrivateKey_NullFilePath_ThrowsArgumentException() { }
}
```

## API Design Principles

### Public Surface
- **OpenSslFacade**: Primary public API - simplified, opinionated methods
- **OpenSLLWrapper**: Lower-level API - more control, advanced scenarios

### Method Overloads Pattern
Each operation provides multiple overloads:
```csharp
// File-based
void GenerateRsaPrivateKey(string outputPath, int keySize = 4096);
Task GenerateRsaPrivateKeyAsync(string outputPath, int keySize = 4096, CancellationToken ct = default);

// Stream-based
void GenerateRsaPrivateKey(Stream outputStream, int keySize = 4096);

// Memory-based
byte[] GenerateRsaPrivateKeyBytes(int keySize = 4096);
```

### Error Handling Strategy
```csharp
/// <exception cref="ArgumentNullException">Thrown when outputPath is null.</exception>
/// <exception cref="ArgumentException">Thrown when outputPath is empty or keySize is invalid.</exception>
/// <exception cref="DirectoryNotFoundException">Thrown when directory does not exist.</exception>
public static void GenerateRsaPrivateKey(string outputPath, int keySize = 4096)
{
    if (outputPath == null) throw new ArgumentNullException(nameof(outputPath));
    if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException("Output path cannot be empty.", nameof(outputPath));
    if (keySize < 1024) throw new ArgumentException("Key size must be at least 1024 bits.", nameof(keySize));
    // Implementation...
}
```

## XML Documentation Standards

All public APIs must include comprehensive XML documentation:

```csharp
/// <summary>
/// Generate an RSA private key and write it as a PEM file (PKCS#1 RSA PRIVATE KEY).
/// </summary>
/// <param name="outputPath">File path to write the PEM private key. Must not be null or empty.</param>
/// <param name="keySize">Key size in bits. Common values are 2048, 3072, and 4096. Default is 4096.</param>
/// <exception cref="ArgumentNullException">Thrown when <paramref name="outputPath"/> is null.</exception>
/// <exception cref="ArgumentException">Thrown when <paramref name="outputPath"/> is empty or <paramref name="keySize"/> is invalid.</exception>
/// <example>
/// <code>
/// // Generate a 2048-bit RSA key
/// OpenSslFacade.GenerateRsaPrivateKey("private_key.pem", 2048);
/// </code>
/// </example>
```

## Build and Packaging

### Local Development
```bash
# Build for all targets
dotnet build

# Test
dotnet test OpenSLLWrapper.UnitTests/ --logger "console;verbosity=normal"

# Package locally
dotnet pack OpenSLLWrapper/ -c Release -o artifacts/
```

### CI/CD Pipeline
- **Trigger**: Git tags (`v*`) or releases
- **Steps**: 
  1. Restore dependencies
  2. Build Release configuration
  3. Run unit tests (`dotnet test`)
  4. Run integration tests (MSBuild + VSTest)
  5. Package with version from tag
  6. Validate package contents (README.md, icon.png)
  7. Push to NuGet.org

### Package Metadata
```xml
<PropertyGroup>
  <Version>1.0.3</Version>
  <Authors>OpenSLLWrapper Contributors</Authors>
  <Description>Managed .NET wrapper for RSA key operations, PEM conversions and signing/verification using BouncyCastle.</Description>
  <PackageLicenseExpression>MIT</PackageLicenseExpression>
  <PackageReadmeFile>README.md</PackageReadmeFile>
  <PackageIcon>icon.png</PackageIcon>
  <IncludeSymbols>true</IncludeSymbols>
  <SymbolPackageFormat>snupkg</SymbolPackageFormat>
</PropertyGroup>
```

## Cryptographic Implementation Notes

### Key Generation
- Uses BouncyCastle's `RsaKeyPairGenerator`
- Default: PKCS#1 format for compatibility
- Supports PKCS#8 conversion

### Signing/Verification
- **Default**: PKCS#1 v1.5 with SHA-256 (OpenSSL compatible)
- **Optional**: RSASSA-PSS with SHA-256
- Base64 encoding for challenge/signature exchange

### Security Considerations
- No private key caching in memory
- Secure file ACLs on Windows (when available)
- Password-based encryption for PKCS#8
- Clear error messages without exposing sensitive data

## Contributing Guidelines

### Code Style
- Follow .NET Framework 4.7.2 and C# 7.3 conventions
- Use `var` only when type is obvious
- XML documentation on all public APIs
- Comprehensive error handling with meaningful exceptions

### Pull Request Process
1. Create comprehensive unit tests for new functionality
2. Update XML documentation
3. Ensure all tests pass locally
4. Update README.md if adding new features
5. Maintain backwards compatibility for public APIs

### Performance Considerations
- Avoid unnecessary allocations in hot paths
- Prefer streaming over loading entire files into memory
- Benchmark significant changes using `BenchmarkSuite1`

## Debugging and Troubleshooting

### Common Issues
1. **Package reference errors**: Check multi-targeting compatibility
2. **Test failures**: Verify BouncyCastle version consistency
3. **OpenSSL interop**: Ensure OpenSSL is in PATH for integration tests

### Logging
```csharp
// Use the built-in logging infrastructure
Log.Info("Generated RSA key with {KeySize} bits", keySize);
Log.Error(ex, "Failed to generate key");
```

### Performance Profiling
Use the included benchmark suite:
```bash
dotnet run --project BenchmarkSuite1 -c Release
```