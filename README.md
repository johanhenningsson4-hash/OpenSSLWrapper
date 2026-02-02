# OpenSLLWrapper

Version: 1.0.3

Release: v1.0.3

This release includes a small version bump and packaging/CI updates:
- Packaging now uses SDK-style `dotnet pack` (no `.nuspec`) and includes README + icon in the nupkg.
- A symbols package (`.snupkg`) is generated and pushed to NuGet.
- CI validates produced `.nupkg` contains `README.md` and `icon.png` and runs the test suite before packaging.
- Tests project has been converted to an SDK-style project so CI uses `dotnet test`.

Managed .NET wrapper for RSA key operations, PEM conversions and signing/verification using BouncyCastle.

Features
- Generate RSA private keys (PKCS#1 PEM) and export as bytes/streams/files.
- Create Certificate Signing Requests (CSR) from private key PEMs.
- Sign raw data and base64-encoded challenges using SHA256withRSA (PKCS#1 v1.5) and optional RSASSA-PSS (SHA-256).
- Verify signatures (file/stream/byte[] overloads) for both PKCS#1-v1_5 and PSS.
- Convert between PKCS#1 and PKCS#8 PEM formats (file/stream/byte[]).
- Export public key PEM derived from a private key PEM.
- Export/import encrypted PKCS#8 (password-protected) PEM.
- All operations provide stream and byte[] overloads to avoid filesystem I/O.
- Async Task wrappers for file-based operations.

Requirements
- .NET Framework 4.7.2
- BouncyCastle (package referenced in project: BouncyCastle.Cryptography 2.6.2)
- (Optional) OpenSSL on PATH for interoperability tests

Projects
- `OpenSLLWrapper` - library with all helpers (uses BouncyCastle)
- `OpenSLLWrapper.Tests` - console test runner that exercises generation, CSR, signing, conversion and OpenSSL interoperability checks (if OpenSSL is available)

Quick start
1. Restore NuGet packages (restore `packages.config` in `OpenSLLWrapper`).
2. Build solution (Visual Studio or MSBuild).
3. Use the `OpenSslFacade` class as the public API entry point, for example:

```csharp
// generate key
OpenSslFacade.GenerateRsaPrivateKey("private_key.pem", 2048);

// export public key
OpenSslFacade.ExportPublicKeyPemFromPrivateKey("private_key.pem", "public_key.pem");

// sign challenge (base64->signature-base64)
string challengeB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello"));
string sigB64 = OpenSslFacade.SignBase64Challenge(challengeB64, "private_key.pem");

// verify signature
bool ok = OpenSLLWrapper.VerifyBase64Signature(challengeB64, sigB64, "public_key.pem");
```

Running tests / examples
- The console test runner is `OpenSLLWrapper.Tests` — build and run the executable. It will generate temporary files and run interoperability checks with OpenSSL if available.

OpenSSL interoperability
- The library defaults to PKCS#1 v1.5 signatures (`SHA256withRSA`) to match OpenSSL `dgst -sha256 -sign` and `dgst -sha256 -verify` behavior.
- Use `usePss=true` on signing/verification methods to enable RSASSA-PSS (both sides must agree on PSS params).

Security notes
- Keep private keys and passwords secure. The library writes PEM files as ASCII and does not manage OS-level protection.
- Encrypted PKCS#8 uses PBE-SHA1-3DES for compatibility; change to PBES2/AES if stronger protection is required.

Contributing
- Build/test with Visual Studio 2019/2022 targeting .NET Framework 4.7.2.
- Add unit tests under a test framework (xUnit/NUnit/MSTest) for CI integration.

License
- Check repository root for license information.

Secure PEM storage examples
 - Save a PEM file and restrict filesystem ACLs (Windows):

```csharp
// Generate private key bytes
var pkPem = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(2048);
// Save to file and restrict ACLs so only current user can access
OpenSLLWrapper.SavePemFileSecure("C:\\keys\\private_key.pem", pkPem);
```

 - Password-protect PEM file (portable):

```csharp
var pkPem = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(2048);
string password = "s3cureP@ssw0rd";
OpenSLLWrapper.SavePemFileEncrypted("C:\\keys\\private_key.enc", pkPem, password);

// Later: read and decrypt
byte[] decrypted = OpenSLLWrapper.LoadPemFileEncrypted("C:\\keys\\private_key.enc", password);
// Use the decrypted bytes (PEM) with existing helpers
var pubPem = OpenSLLWrapper.ExportPublicKeyPemFromPrivateKeyBytes(decrypted);
```

Notes
- `SavePemFileSecure` attempts to restrict filesystem ACLs on Windows only; on non-Windows platforms it will write the file without ACL modifications.
- `SavePemFileEncrypted` uses a password-based scheme (PBKDF2 with HMAC-SHA256, AES-256-CBC and HMAC-SHA256 for integrity). Keep your password secure and consider using a stronger iteration count for high-security scenarios.
