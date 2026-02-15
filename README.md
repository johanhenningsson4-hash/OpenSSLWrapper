# OpenSLLWrapper

Version: 1.2.1

Release: v1.2.1

This patch release includes minor updates and improvements:

**Updates (v1.2.1):**
- Documentation improvements and code refinements
- Enhanced error handling and validation
- Performance optimizations for configuration management
- Updated dependencies and build pipeline improvements

**Features (v1.2.0):**
- **SSH Key Support**: Convert between PEM and OpenSSH formats for public/private keys
- **Enhanced Configuration**: Centralized configuration management with performance tuning and security policies
- **Key Pair Generation**: Direct SSH key pair generation with comments and passphrase protection
- **SSH Key Validation**: Format validation and metadata extraction for SSH public keys
- **Performance Controls**: Configurable signer pooling, caching, and parallelism settings

**Previous Features (v1.1.0):**
- **Certificate Management**: Create self-signed certificates, sign CSRs, convert PEM?PFX formats, certificate validation
- **JWT Operations**: Create and verify JSON Web Tokens with RSA signatures (RS256, RS384, RS512, PS256, PS384, PS512)
- **JWS Operations**: Sign and verify JSON Web Signatures for arbitrary JSON payloads
- **JWE Operations**: Encrypt and decrypt JSON payloads with RSA public/private keys (RSA-OAEP, A256GCM)
- **Type-safe APIs**: Strongly-typed result objects with helper methods for claim extraction
- **Comprehensive Test Coverage**: 60+ unit tests covering new certificate and JOSE functionality

Managed .NET wrapper for RSA key operations, PEM conversions, signing/verification, certificate management, and JOSE operations using BouncyCastle.

Features
- **RSA Key Operations**: Generate RSA private keys (PKCS#1 PEM) and export as bytes/streams/files
- **Certificate Signing Requests (CSR)**: Create CSRs from private key PEMs
- **Digital Signatures**: Sign raw data and base64-encoded challenges using SHA256withRSA (PKCS#1 v1.5) and optional RSASSA-PSS (SHA-256)
- **Signature Verification**: Verify signatures (file/stream/byte[] overloads) for both PKCS#1-v1_5 and PSS
- **Format Conversions**: Convert between PKCS#1 and PKCS#8 PEM formats (file/stream/byte[])
- **Public Key Export**: Export public key PEM derived from a private key PEM
- **Encrypted Keys**: Export/import encrypted PKCS#8 (password-protected) PEM
- **Certificate Management**: Create self-signed certificates, sign CSRs, convert between PEM/PFX formats
- **JOSE Operations**: JWT creation/verification, JWS signing/verification, JWE encryption/decryption
- **SSH Key Support**: Convert PEM?SSH formats, generate SSH key pairs, validate SSH key formats
- **Configuration Management**: Centralized settings for performance, security policies, and operational behavior
- **Stream Support**: All operations provide stream and byte[] overloads to avoid filesystem I/O
- **Async Support**: Task wrappers for file-based operations

Requirements
- .NET Framework 4.7.2
- BouncyCastle (package referenced in project: BouncyCastle.Cryptography 2.6.2)
- (Optional) OpenSSL on PATH for interoperability tests

Projects
- `OpenSLLWrapper` - main library with RSA operations, certificate management, and JOSE support (uses BouncyCastle)
- `OpenSLLWrapper.Tests` - console test runner that exercises generation, CSR, signing, conversion and OpenSSL interoperability checks (if OpenSSL is available)
- `OpenSLLWrapper.UnitTests` - comprehensive unit test suite with MSTest framework covering all major functionality

Quick start
1. Restore NuGet packages (restore `packages.config` in `OpenSLLWrapper`).
2. Build solution (Visual Studio or MSBuild).
3. Use the facade classes as public API entry points:

**RSA Operations** (`OpenSslFacade`):
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

**Certificate Operations** (`CertificateFacade`):
```csharp
// create self-signed certificate
var cert = CertificateFacade.CreateSelfSignedCertificate(
    "private_key.pem", 
    "CN=test.example.com,O=Test Corp", 
    TimeSpan.FromDays(365));

// convert PEM to PFX
CertificateFacade.ConvertPemToPfx(
    "certificate.pem", 
    "private_key.pem", 
    "certificate.pfx", 
    "password");
```

**JWT Operations** (`JoseFacade`):
```csharp
// create JWT
var payload = new { userId = 123, username = "john", roles = new[] { "user" } };
string jwt = JoseFacade.CreateJwt(
    payload, 
    "jwt_private_key.pem", 
    expirationMinutes: 30,
    issuer: "MyApp");

// verify JWT
var result = JoseFacade.VerifyJwt(jwt, "jwt_public_key.pem", expectedIssuer: "MyApp");
if (result.IsValid)
{
    Console.WriteLine($"User ID: {result.GetClaim<int>("userId")}");
}
```

**SSH Key Operations** (`SshKeyFacade`):
```csharp
// generate SSH key pair
var keyPair = SshKeyFacade.GenerateSshKeyPair(
    keySize: 2048,
    comment: "user@workstation",
    privateKeyPassphrase: "secure_passphrase");

// save to SSH directory
File.WriteAllText("~/.ssh/id_rsa.pub", keyPair.PublicKey);
File.WriteAllBytes("~/.ssh/id_rsa", keyPair.PrivateKeyBytes);

// convert existing PEM to SSH format
string sshPublicKey = SshKeyFacade.ConvertPemToSshPublicKey(
    "public_key.pem", 
    "user@example.com");
```

**Configuration Management** (`OpenSslWrapperConfig`):
```csharp
// configure default settings
OpenSslWrapperConfig.DefaultKeySize = 4096;
OpenSslWrapperConfig.DefaultJwtAlgorithm = JwtAlgorithm.PS256;
OpenSslWrapperConfig.DefaultJwtExpirationMinutes = 30;

// performance tuning
OpenSslWrapperConfig.SignerPoolSize = 8;
OpenSslWrapperConfig.MaxDegreeOfParallelism = 4;

// security policies
OpenSslWrapperConfig.MinimumKeySize = 2048;
OpenSslWrapperConfig.SetAllowedJwtAlgorithms(new[] {
    JwtAlgorithm.PS256, JwtAlgorithm.PS384, JwtAlgorithm.PS512
});

// get current configuration
var config = OpenSslWrapperConfig.GetCurrentConfiguration();
Console.WriteLine(config.ToString());
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
