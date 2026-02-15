using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Facade for JSON Object Signing and Encryption (JOSE) operations including JWT, JWS, and JWE.
    /// Provides high-level JWT creation, verification, and manipulation built on BouncyCastle.
    /// </summary>
    /// <remarks>
    /// This facade handles common JOSE operations such as:
    /// - Creating and verifying JSON Web Tokens (JWT) with RSA signatures
    /// - JSON Web Signature (JWS) operations for general JSON payload signing
    /// - JSON Web Encryption (JWE) operations for payload encryption
    /// - Support for standard algorithms: RS256, RS384, RS512, PS256, PS384, PS512
    /// All methods follow the library's pattern of providing file and byte array overloads where applicable.
    /// </remarks>
    public static class JoseFacade
    {
        /// <summary>
        /// Create a JSON Web Token (JWT) with the specified payload and sign it using an RSA private key.
        /// The JWT will include standard claims (iat, exp) along with the provided payload.
        /// </summary>
        /// <param name="payload">The payload object to encode in the JWT. Will be serialized to JSON.</param>
        /// <param name="privateKeyPath">Path to the RSA private key PEM file for signing. Must not be null or empty.</param>
        /// <param name="algorithm">The signing algorithm to use. Default is RS256.</param>
        /// <param name="expirationMinutes">JWT expiration time in minutes from now. Default is 60 minutes.</param>
        /// <param name="issuer">The issuer (iss) claim for the JWT. Can be null.</param>
        /// <param name="audience">The audience (aud) claim for the JWT. Can be null.</param>
        /// <returns>A base64url-encoded JWT string ready for transmission.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Create a JWT for user authentication
        /// var userPayload = new { 
        ///     userId = 12345, 
        ///     username = "john.doe",
        ///     roles = new[] { "user", "admin" }
        /// };
        /// 
        /// string jwt = JoseFacade.CreateJwt(
        ///     userPayload, 
        ///     "jwt_private_key.pem",
        ///     JwtAlgorithm.RS256,
        ///     expirationMinutes: 30,
        ///     issuer: "MyApp",
        ///     audience: "api.example.com");
        /// 
        /// Console.WriteLine($"JWT: {jwt}");
        /// </code>
        /// </example>
        public static string CreateJwt(
            object payload, 
            string privateKeyPath, 
            JwtAlgorithm algorithm = JwtAlgorithm.RS256,
            int expirationMinutes = 60,
            string issuer = null,
            string audience = null)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (privateKeyPath == null) throw new ArgumentNullException(nameof(privateKeyPath));
            if (string.IsNullOrWhiteSpace(privateKeyPath)) throw new ArgumentException("Private key path cannot be empty.", nameof(privateKeyPath));
            if (expirationMinutes <= 0) throw new ArgumentException("Expiration minutes must be positive.", nameof(expirationMinutes));

            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyPath);
            return CreateJwt(payload, privateKeyBytes, algorithm, expirationMinutes, issuer, audience);
        }

        /// <summary>
        /// Create a JSON Web Token (JWT) using private key bytes for in-memory processing.
        /// This method allows for JWT creation without requiring filesystem access.
        /// </summary>
        /// <param name="payload">The payload object to encode in the JWT. Will be serialized to JSON.</param>
        /// <param name="privateKeyPem">The RSA private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="algorithm">The signing algorithm to use. Default is RS256.</param>
        /// <param name="expirationMinutes">JWT expiration time in minutes from now. Default is 60 minutes.</param>
        /// <param name="issuer">The issuer (iss) claim for the JWT. Can be null.</param>
        /// <param name="audience">The audience (aud) claim for the JWT. Can be null.</param>
        /// <returns>A base64url-encoded JWT string ready for transmission.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Create JWT in memory
        /// byte[] privateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// var claims = new { sub = "user123", name = "John Doe" };
        /// 
        /// string jwt = JoseFacade.CreateJwt(
        ///     claims, 
        ///     privateKey, 
        ///     JwtAlgorithm.RS256, 
        ///     expirationMinutes: 15);
        /// </code>
        /// </example>
        public static string CreateJwt(
            object payload, 
            byte[] privateKeyPem, 
            JwtAlgorithm algorithm = JwtAlgorithm.RS256,
            int expirationMinutes = 60,
            string issuer = null,
            string audience = null)
        {
            return OpenSLLWrapper.CreateJwt(payload, privateKeyPem, algorithm, expirationMinutes, issuer, audience);
        }

        /// <summary>
        /// Verify a JSON Web Token (JWT) and extract its payload using an RSA public key.
        /// This method validates the JWT signature, expiration, and other standard claims.
        /// </summary>
        /// <param name="jwt">The JWT string to verify. Must not be null or empty.</param>
        /// <param name="publicKeyPath">Path to the RSA public key PEM file for verification. Must not be null or empty.</param>
        /// <param name="expectedIssuer">Expected issuer (iss) claim. If specified, must match the JWT's issuer. Can be null to skip validation.</param>
        /// <param name="expectedAudience">Expected audience (aud) claim. If specified, must match the JWT's audience. Can be null to skip validation.</param>
        /// <param name="clockSkewMinutes">Allowed clock skew for expiration validation in minutes. Default is 5 minutes.</param>
        /// <returns>A JwtValidationResult containing the validation status and decoded payload if valid.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the public key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Verify a received JWT
        /// string incomingJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...";
        /// 
        /// var result = JoseFacade.VerifyJwt(
        ///     incomingJwt, 
        ///     "jwt_public_key.pem",
        ///     expectedIssuer: "MyApp",
        ///     expectedAudience: "api.example.com");
        /// 
        /// if (result.IsValid)
        /// {
        ///     Console.WriteLine($"JWT is valid. Payload: {result.PayloadJson}");
        ///     var userId = result.GetClaim&lt;int&gt;("userId");
        ///     Console.WriteLine($"User ID: {userId}");
        /// }
        /// else
        /// {
        ///     Console.WriteLine($"JWT validation failed: {result.ErrorMessage}");
        /// }
        /// </code>
        /// </example>
        public static JwtValidationResult VerifyJwt(
            string jwt, 
            string publicKeyPath,
            string expectedIssuer = null,
            string expectedAudience = null,
            int clockSkewMinutes = 5)
        {
            if (jwt == null) throw new ArgumentNullException(nameof(jwt));
            if (string.IsNullOrWhiteSpace(jwt)) throw new ArgumentException("JWT cannot be empty.", nameof(jwt));
            if (publicKeyPath == null) throw new ArgumentNullException(nameof(publicKeyPath));
            if (string.IsNullOrWhiteSpace(publicKeyPath)) throw new ArgumentException("Public key path cannot be empty.", nameof(publicKeyPath));
            if (clockSkewMinutes < 0) throw new ArgumentException("Clock skew minutes cannot be negative.", nameof(clockSkewMinutes));

            byte[] publicKeyBytes = File.ReadAllBytes(publicKeyPath);
            return VerifyJwt(jwt, publicKeyBytes, expectedIssuer, expectedAudience, clockSkewMinutes);
        }

        /// <summary>
        /// Verify a JSON Web Token (JWT) using public key bytes for in-memory processing.
        /// This method provides JWT verification without requiring filesystem access.
        /// </summary>
        /// <param name="jwt">The JWT string to verify. Must not be null or empty.</param>
        /// <param name="publicKeyPem">The RSA public key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="expectedIssuer">Expected issuer (iss) claim. If specified, must match the JWT's issuer. Can be null to skip validation.</param>
        /// <param name="expectedAudience">Expected audience (aud) claim. If specified, must match the JWT's audience. Can be null to skip validation.</param>
        /// <param name="clockSkewMinutes">Allowed clock skew for expiration validation in minutes. Default is 5 minutes.</param>
        /// <returns>A JwtValidationResult containing the validation status and decoded payload if valid.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Verify JWT in memory
        /// byte[] publicKey = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(privateKeyBytes);
        /// var result = JoseFacade.VerifyJwt(jwtString, publicKey);
        /// 
        /// if (result.IsValid)
        /// {
        ///     Console.WriteLine("JWT signature and claims are valid");
        /// }
        /// </code>
        /// </example>
        public static JwtValidationResult VerifyJwt(
            string jwt, 
            byte[] publicKeyPem,
            string expectedIssuer = null,
            string expectedAudience = null,
            int clockSkewMinutes = 5)
        {
            return OpenSLLWrapper.VerifyJwt(jwt, publicKeyPem, expectedIssuer, expectedAudience, clockSkewMinutes);
        }

        /// <summary>
        /// Create a JSON Web Signature (JWS) for a general JSON payload using an RSA private key.
        /// JWS provides digital signatures for JSON data without the structure restrictions of JWT.
        /// </summary>
        /// <param name="jsonPayload">The JSON payload string to sign. Must not be null or empty.</param>
        /// <param name="privateKeyPath">Path to the RSA private key PEM file for signing. Must not be null or empty.</param>
        /// <param name="algorithm">The signing algorithm to use. Default is RS256.</param>
        /// <param name="additionalHeaders">Additional headers to include in the JWS header. Can be null.</param>
        /// <returns>A JWS compact serialization string ready for transmission.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Sign arbitrary JSON data
        /// string jsonData = @"{""message"":""Hello, World!"",""timestamp"":""2024-01-01T12:00:00Z""}";
        /// var customHeaders = new Dictionary&lt;string, object&gt; { {"typ", "custom"} };
        /// 
        /// string jws = JoseFacade.SignJws(
        ///     jsonData, 
        ///     "signing_key.pem", 
        ///     JwtAlgorithm.RS256,
        ///     customHeaders);
        /// 
        /// Console.WriteLine($"JWS: {jws}");
        /// </code>
        /// </example>
        public static string SignJws(
            string jsonPayload, 
            string privateKeyPath, 
            JwtAlgorithm algorithm = JwtAlgorithm.RS256,
            Dictionary<string, object> additionalHeaders = null)
        {
            if (jsonPayload == null) throw new ArgumentNullException(nameof(jsonPayload));
            if (string.IsNullOrWhiteSpace(jsonPayload)) throw new ArgumentException("JSON payload cannot be empty.", nameof(jsonPayload));
            if (privateKeyPath == null) throw new ArgumentNullException(nameof(privateKeyPath));
            if (string.IsNullOrWhiteSpace(privateKeyPath)) throw new ArgumentException("Private key path cannot be empty.", nameof(privateKeyPath));

            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyPath);
            return SignJws(jsonPayload, privateKeyBytes, algorithm, additionalHeaders);
        }

        /// <summary>
        /// Create a JSON Web Signature (JWS) using private key bytes for in-memory processing.
        /// This method allows for JWS creation without requiring filesystem access.
        /// </summary>
        /// <param name="jsonPayload">The JSON payload string to sign. Must not be null or empty.</param>
        /// <param name="privateKeyPem">The RSA private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="algorithm">The signing algorithm to use. Default is RS256.</param>
        /// <param name="additionalHeaders">Additional headers to include in the JWS header. Can be null.</param>
        /// <returns>A JWS compact serialization string ready for transmission.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Sign JSON payload in memory
        /// byte[] privateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// string json = @"{""data"":""sensitive information""}";
        /// 
        /// string jws = JoseFacade.SignJws(json, privateKey, JwtAlgorithm.RS256);
        /// </code>
        /// </example>
        public static string SignJws(
            string jsonPayload, 
            byte[] privateKeyPem, 
            JwtAlgorithm algorithm = JwtAlgorithm.RS256,
            Dictionary<string, object> additionalHeaders = null)
        {
            return OpenSLLWrapper.SignJws(jsonPayload, privateKeyPem, algorithm, additionalHeaders);
        }

        /// <summary>
        /// Verify a JSON Web Signature (JWS) and extract its payload using an RSA public key.
        /// This method validates the JWS signature and returns the original JSON payload if valid.
        /// </summary>
        /// <param name="jws">The JWS string to verify. Must not be null or empty.</param>
        /// <param name="publicKeyPath">Path to the RSA public key PEM file for verification. Must not be null or empty.</param>
        /// <returns>A JwsValidationResult containing the validation status and decoded payload if valid.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the public key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Verify a received JWS
        /// string incomingJws = "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9...";
        /// 
        /// var result = JoseFacade.VerifyJws(incomingJws, "verification_public_key.pem");
        /// 
        /// if (result.IsValid)
        /// {
        ///     Console.WriteLine($"JWS is valid. Payload: {result.PayloadJson}");
        /// }
        /// else
        /// {
        ///     Console.WriteLine($"JWS validation failed: {result.ErrorMessage}");
        /// }
        /// </code>
        /// </example>
        public static JwsValidationResult VerifyJws(string jws, string publicKeyPath)
        {
            if (jws == null) throw new ArgumentNullException(nameof(jws));
            if (string.IsNullOrWhiteSpace(jws)) throw new ArgumentException("JWS cannot be empty.", nameof(jws));
            if (publicKeyPath == null) throw new ArgumentNullException(nameof(publicKeyPath));
            if (string.IsNullOrWhiteSpace(publicKeyPath)) throw new ArgumentException("Public key path cannot be empty.", nameof(publicKeyPath));

            byte[] publicKeyBytes = File.ReadAllBytes(publicKeyPath);
            return VerifyJws(jws, publicKeyBytes);
        }

        /// <summary>
        /// Verify a JSON Web Signature (JWS) using public key bytes for in-memory processing.
        /// This method provides JWS verification without requiring filesystem access.
        /// </summary>
        /// <param name="jws">The JWS string to verify. Must not be null or empty.</param>
        /// <param name="publicKeyPem">The RSA public key in PEM format as a byte array. Must not be null or empty.</param>
        /// <returns>A JwsValidationResult containing the validation status and decoded payload if valid.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Verify JWS in memory
        /// byte[] publicKey = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(privateKeyBytes);
        /// var result = JoseFacade.VerifyJws(jwsString, publicKey);
        /// 
        /// if (result.IsValid)
        /// {
        ///     var originalData = result.PayloadJson;
        ///     Console.WriteLine($"Original data: {originalData}");
        /// }
        /// </code>
        /// </example>
        public static JwsValidationResult VerifyJws(string jws, byte[] publicKeyPem)
        {
            return OpenSLLWrapper.VerifyJws(jws, publicKeyPem);
        }

        /// <summary>
        /// Encrypt a JSON payload using JSON Web Encryption (JWE) with an RSA public key.
        /// This creates an encrypted JWE that can only be decrypted with the corresponding private key.
        /// </summary>
        /// <param name="jsonPayload">The JSON payload string to encrypt. Must not be null or empty.</param>
        /// <param name="publicKeyPath">Path to the RSA public key PEM file for encryption. Must not be null or empty.</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm to use. Default is RSA-OAEP.</param>
        /// <param name="contentEncryptionAlgorithm">The content encryption algorithm to use. Default is A256GCM.</param>
        /// <returns>A JWE compact serialization string ready for transmission.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the public key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Encrypt sensitive JSON data
        /// string sensitiveData = @"{""ssn"":""123-45-6789"",""creditCard"":""4111-1111-1111-1111""}";
        /// 
        /// string jwe = JoseFacade.EncryptJwe(
        ///     sensitiveData, 
        ///     "recipient_public_key.pem",
        ///     JweKeyAlgorithm.RsaOaep,
        ///     JweContentAlgorithm.A256Gcm);
        /// 
        /// Console.WriteLine($"Encrypted JWE: {jwe}");
        /// </code>
        /// </example>
        public static string EncryptJwe(
            string jsonPayload, 
            string publicKeyPath,
            JweKeyAlgorithm keyEncryptionAlgorithm = JweKeyAlgorithm.RsaOaep,
            JweContentAlgorithm contentEncryptionAlgorithm = JweContentAlgorithm.A256Gcm)
        {
            if (jsonPayload == null) throw new ArgumentNullException(nameof(jsonPayload));
            if (string.IsNullOrWhiteSpace(jsonPayload)) throw new ArgumentException("JSON payload cannot be empty.", nameof(jsonPayload));
            if (publicKeyPath == null) throw new ArgumentNullException(nameof(publicKeyPath));
            if (string.IsNullOrWhiteSpace(publicKeyPath)) throw new ArgumentException("Public key path cannot be empty.", nameof(publicKeyPath));

            byte[] publicKeyBytes = File.ReadAllBytes(publicKeyPath);
            return EncryptJwe(jsonPayload, publicKeyBytes, keyEncryptionAlgorithm, contentEncryptionAlgorithm);
        }

        /// <summary>
        /// Encrypt a JSON payload using JSON Web Encryption (JWE) with public key bytes for in-memory processing.
        /// This method allows for JWE creation without requiring filesystem access.
        /// </summary>
        /// <param name="jsonPayload">The JSON payload string to encrypt. Must not be null or empty.</param>
        /// <param name="publicKeyPem">The RSA public key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="keyEncryptionAlgorithm">The key encryption algorithm to use. Default is RSA-OAEP.</param>
        /// <param name="contentEncryptionAlgorithm">The content encryption algorithm to use. Default is A256GCM.</param>
        /// <returns>A JWE compact serialization string ready for transmission.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Encrypt payload in memory
        /// byte[] publicKey = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(privateKeyBytes);
        /// string secretData = @"{""apiKey"":""secret123"",""token"":""xyz789""}";
        /// 
        /// string jwe = JoseFacade.EncryptJwe(secretData, publicKey);
        /// </code>
        /// </example>
        public static string EncryptJwe(
            string jsonPayload, 
            byte[] publicKeyPem,
            JweKeyAlgorithm keyEncryptionAlgorithm = JweKeyAlgorithm.RsaOaep,
            JweContentAlgorithm contentEncryptionAlgorithm = JweContentAlgorithm.A256Gcm)
        {
            return OpenSLLWrapper.EncryptJwe(jsonPayload, publicKeyPem, keyEncryptionAlgorithm, contentEncryptionAlgorithm);
        }

        /// <summary>
        /// Decrypt a JSON Web Encryption (JWE) and extract its payload using an RSA private key.
        /// This method decrypts a JWE and returns the original JSON payload.
        /// </summary>
        /// <param name="jwe">The JWE string to decrypt. Must not be null or empty.</param>
        /// <param name="privateKeyPath">Path to the RSA private key PEM file for decryption. Must not be null or empty.</param>
        /// <returns>A JweDecryptionResult containing the decryption status and original payload if successful.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Decrypt a received JWE
        /// string encryptedJwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ...";
        /// 
        /// var result = JoseFacade.DecryptJwe(encryptedJwe, "recipient_private_key.pem");
        /// 
        /// if (result.IsSuccessful)
        /// {
        ///     Console.WriteLine($"Decrypted payload: {result.PayloadJson}");
        /// }
        /// else
        /// {
        ///     Console.WriteLine($"JWE decryption failed: {result.ErrorMessage}");
        /// }
        /// </code>
        /// </example>
        public static JweDecryptionResult DecryptJwe(string jwe, string privateKeyPath)
        {
            if (jwe == null) throw new ArgumentNullException(nameof(jwe));
            if (string.IsNullOrWhiteSpace(jwe)) throw new ArgumentException("JWE cannot be empty.", nameof(jwe));
            if (privateKeyPath == null) throw new ArgumentNullException(nameof(privateKeyPath));
            if (string.IsNullOrWhiteSpace(privateKeyPath)) throw new ArgumentException("Private key path cannot be empty.", nameof(privateKeyPath));

            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyPath);
            return DecryptJwe(jwe, privateKeyBytes);
        }

        /// <summary>
        /// Decrypt a JSON Web Encryption (JWE) using private key bytes for in-memory processing.
        /// This method provides JWE decryption without requiring filesystem access.
        /// </summary>
        /// <param name="jwe">The JWE string to decrypt. Must not be null or empty.</param>
        /// <param name="privateKeyPem">The RSA private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <returns>A JweDecryptionResult containing the decryption status and original payload if successful.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Decrypt JWE in memory
        /// byte[] privateKey = File.ReadAllBytes("private_key.pem");
        /// var result = JoseFacade.DecryptJwe(jweString, privateKey);
        /// 
        /// if (result.IsSuccessful)
        /// {
        ///     var originalData = result.PayloadJson;
        ///     Console.WriteLine($"Decrypted: {originalData}");
        /// }
        /// </code>
        /// </example>
        public static JweDecryptionResult DecryptJwe(string jwe, byte[] privateKeyPem)
        {
            return OpenSLLWrapper.DecryptJwe(jwe, privateKeyPem);
        }
    }
}