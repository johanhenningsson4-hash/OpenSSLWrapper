using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Represents the result of JWT validation operations.
    /// </summary>
    public class JwtValidationResult
    {
        /// <summary>
        /// Gets a value indicating whether the JWT is valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets the error message if validation failed, or null if validation succeeded.
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets the decoded payload as a JSON string if validation succeeded, or null if validation failed.
        /// </summary>
        public string PayloadJson { get; set; }

        /// <summary>
        /// Gets the JWT header information if validation succeeded, or null if validation failed.
        /// </summary>
        public Dictionary<string, object> Header { get; set; }

        /// <summary>
        /// Gets the JWT claims as a dictionary if validation succeeded, or null if validation failed.
        /// </summary>
        public Dictionary<string, object> Claims { get; set; }

        /// <summary>
        /// Gets the expiration time of the JWT if validation succeeded, or null if validation failed or no expiration claim exists.
        /// </summary>
        public DateTime? ExpirationTime { get; set; }

        /// <summary>
        /// Gets the issued at time of the JWT if validation succeeded, or null if validation failed or no issued at claim exists.
        /// </summary>
        public DateTime? IssuedAt { get; set; }

        /// <summary>
        /// Gets a strongly-typed claim value from the JWT payload.
        /// </summary>
        /// <typeparam name="T">The type to convert the claim value to.</typeparam>
        /// <param name="claimName">The name of the claim to retrieve.</param>
        /// <returns>The claim value converted to the specified type, or the default value of T if the claim doesn't exist or conversion fails.</returns>
        public T GetClaim<T>(string claimName)
        {
            if (Claims == null || !Claims.TryGetValue(claimName, out var value))
                return default(T);

            try
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return default(T);
            }
        }
    }

    /// <summary>
    /// Represents the result of JWS validation operations.
    /// </summary>
    public class JwsValidationResult
    {
        /// <summary>
        /// Gets a value indicating whether the JWS signature is valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets the error message if validation failed, or null if validation succeeded.
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets the decoded payload as a JSON string if validation succeeded, or null if validation failed.
        /// </summary>
        public string PayloadJson { get; set; }

        /// <summary>
        /// Gets the JWS header information if validation succeeded, or null if validation failed.
        /// </summary>
        public Dictionary<string, object> Header { get; set; }
    }

    /// <summary>
    /// Represents the result of JWE decryption operations.
    /// </summary>
    public class JweDecryptionResult
    {
        /// <summary>
        /// Gets a value indicating whether the JWE decryption was successful.
        /// </summary>
        public bool IsSuccessful { get; set; }

        /// <summary>
        /// Gets the error message if decryption failed, or null if decryption succeeded.
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets the decrypted payload as a JSON string if decryption succeeded, or null if decryption failed.
        /// </summary>
        public string PayloadJson { get; set; }

        /// <summary>
        /// Gets the JWE header information if decryption succeeded, or null if decryption failed.
        /// </summary>
        public Dictionary<string, object> Header { get; set; }
    }

    /// <summary>
    /// Represents the result of certificate validation operations.
    /// </summary>
    public class CertificateValidationResult
    {
        /// <summary>
        /// Gets a value indicating whether the certificate is valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets the error message if validation failed, or null if validation succeeded.
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets the certificate chain status flags indicating specific validation issues.
        /// </summary>
        public X509ChainStatusFlags StatusFlags { get; set; }

        /// <summary>
        /// Gets detailed information about each certificate in the chain validation.
        /// </summary>
        public X509ChainStatus[] ChainStatus { get; set; }

        /// <summary>
        /// Gets the validated certificate chain if validation succeeded, or null if validation failed.
        /// </summary>
        public X509Chain Chain { get; set; }
    }

    /// <summary>
    /// Supported JWT/JWS signing algorithms.
    /// </summary>
    public enum JwtAlgorithm
    {
        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-256. Most commonly used and widely supported.
        /// </summary>
        RS256,

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-384. Provides higher security than RS256.
        /// </summary>
        RS384,

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-512. Provides highest security among RSASSA-PKCS1-v1_5 variants.
        /// </summary>
        RS512,

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256. Modern probabilistic signature scheme.
        /// </summary>
        PS256,

        /// <summary>
        /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384. Higher security PSS variant.
        /// </summary>
        PS384,

        /// <summary>
        /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512. Highest security PSS variant.
        /// </summary>
        PS512
    }

    /// <summary>
    /// Supported JWE key encryption algorithms.
    /// </summary>
    public enum JweKeyAlgorithm
    {
        /// <summary>
        /// RSAES-PKCS1-v1_5. Legacy algorithm, use RSA-OAEP for new applications.
        /// </summary>
        Rsa1_5,

        /// <summary>
        /// RSAES OAEP using default parameters. Recommended for new applications.
        /// </summary>
        RsaOaep,

        /// <summary>
        /// RSAES OAEP using SHA-256 and MGF1 with SHA-256. Enhanced security variant.
        /// </summary>
        RsaOaep256
    }

    /// <summary>
    /// Supported JWE content encryption algorithms.
    /// </summary>
    public enum JweContentAlgorithm
    {
        /// <summary>
        /// AES GCM using 128-bit key. Fast and secure for most applications.
        /// </summary>
        A128Gcm,

        /// <summary>
        /// AES GCM using 192-bit key. Higher security than A128GCM.
        /// </summary>
        A192Gcm,

        /// <summary>
        /// AES GCM using 256-bit key. Highest security, recommended for sensitive data.
        /// </summary>
        A256Gcm,

        /// <summary>
        /// AES CBC using 128-bit key with HMAC SHA-256. Legacy algorithm.
        /// </summary>
        A128CbcHS256,

        /// <summary>
        /// AES CBC using 192-bit key with HMAC SHA-384. Legacy algorithm.
        /// </summary>
        A192CbcHS384,

        /// <summary>
        /// AES CBC using 256-bit key with HMAC SHA-512. Legacy algorithm.
        /// </summary>
        A256CbcHS512
    }
}