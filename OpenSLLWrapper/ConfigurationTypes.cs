using System;
using System.Collections.Generic;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Represents an SSH key pair containing both public and private keys in SSH format.
    /// </summary>
    public class SshKeyPair
    {
        /// <summary>
        /// Gets or sets the SSH public key in OpenSSH format (ssh-rsa ...).
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// Gets or sets the SSH private key in OpenSSH format as a byte array.
        /// </summary>
        public byte[] PrivateKeyBytes { get; set; }

        /// <summary>
        /// Gets or sets the comment associated with the SSH key pair.
        /// </summary>
        public string Comment { get; set; }

        /// <summary>
        /// Gets or sets whether the private key is encrypted with a passphrase.
        /// </summary>
        public bool IsPrivateKeyEncrypted { get; set; }

        /// <summary>
        /// Gets the key type (e.g., "ssh-rsa", "ssh-ed25519").
        /// </summary>
        public string KeyType
        {
            get
            {
                if (string.IsNullOrEmpty(PublicKey))
                    return null;
                
                var parts = PublicKey.Split(' ');
                return parts.Length > 0 ? parts[0] : null;
            }
        }

        /// <summary>
        /// Gets the estimated key length in bits based on the public key data.
        /// </summary>
        public int? EstimatedKeyLength
        {
            get
            {
                if (string.IsNullOrEmpty(PublicKey) || KeyType != "ssh-rsa")
                    return null;
                
                try
                {
                    // Rough estimation based on base64 length
                    var parts = PublicKey.Split(' ');
                    if (parts.Length < 2) return null;
                    
                    var base64Data = parts[1];
                    var dataLength = base64Data.Length * 3 / 4; // Approximate decoded length
                    
                    // RSA public key size estimation (very rough)
                    if (dataLength < 300) return 1024;
                    if (dataLength < 400) return 2048;
                    if (dataLength < 500) return 3072;
                    return 4096;
                }
                catch
                {
                    return null;
                }
            }
        }
    }

    /// <summary>
    /// Represents the result of SSH public key format validation.
    /// </summary>
    public class SshKeyValidationResult
    {
        /// <summary>
        /// Gets or sets whether the SSH key format is valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets the error message if validation failed, or null if validation succeeded.
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets the detected key type (e.g., "ssh-rsa", "ssh-ed25519") if validation succeeded.
        /// </summary>
        public string KeyType { get; set; }

        /// <summary>
        /// Gets or sets the estimated key length in bits if validation succeeded and key type supports it.
        /// </summary>
        public int? KeyLength { get; set; }

        /// <summary>
        /// Gets or sets the comment portion of the SSH key if present.
        /// </summary>
        public string Comment { get; set; }

        /// <summary>
        /// Gets or sets whether the key has a valid base64 encoding.
        /// </summary>
        public bool HasValidEncoding { get; set; }

        /// <summary>
        /// Gets or sets additional warnings or informational messages about the key.
        /// </summary>
        public List<string> Warnings { get; set; } = new List<string>();
    }

    /// <summary>
    /// Logging levels for OpenSLLWrapper operations.
    /// </summary>
    public enum LogLevel
    {
        /// <summary>
        /// No logging.
        /// </summary>
        None = 0,

        /// <summary>
        /// Only critical errors that prevent operation.
        /// </summary>
        Error = 1,

        /// <summary>
        /// Warnings about potentially problematic conditions.
        /// </summary>
        Warning = 2,

        /// <summary>
        /// General informational messages about operations.
        /// </summary>
        Information = 3,

        /// <summary>
        /// Detailed information for debugging purposes.
        /// </summary>
        Debug = 4,

        /// <summary>
        /// Very detailed tracing information.
        /// </summary>
        Trace = 5
    }

    /// <summary>
    /// Read-only snapshot of the current OpenSLLWrapper configuration.
    /// </summary>
    public class ConfigurationSnapshot
    {
        /// <summary>
        /// Gets the default RSA key size in bits.
        /// </summary>
        public int DefaultKeySize { get; internal set; }

        /// <summary>
        /// Gets the default JWT signing algorithm.
        /// </summary>
        public JwtAlgorithm DefaultJwtAlgorithm { get; internal set; }

        /// <summary>
        /// Gets the default JWT expiration time in minutes.
        /// </summary>
        public int DefaultJwtExpirationMinutes { get; internal set; }

        /// <summary>
        /// Gets the default clock skew tolerance in minutes.
        /// </summary>
        public int DefaultClockSkewMinutes { get; internal set; }

        /// <summary>
        /// Gets the signer pool size for performance optimization.
        /// </summary>
        public int SignerPoolSize { get; internal set; }

        /// <summary>
        /// Gets whether signer caching is enabled.
        /// </summary>
        public bool SignerCachingEnabled { get; internal set; }

        /// <summary>
        /// Gets the maximum degree of parallelism for batch operations.
        /// </summary>
        public int MaxDegreeOfParallelism { get; internal set; }

        /// <summary>
        /// Gets whether performance counters are enabled.
        /// </summary>
        public bool EnablePerformanceCounters { get; internal set; }

        /// <summary>
        /// Gets the minimum allowed RSA key size in bits.
        /// </summary>
        public int MinimumKeySize { get; internal set; }

        /// <summary>
        /// Gets the set of allowed JWT signing algorithms.
        /// </summary>
        public HashSet<JwtAlgorithm> AllowedJwtAlgorithms { get; internal set; }

        /// <summary>
        /// Gets the set of allowed JWE key encryption algorithms.
        /// </summary>
        public HashSet<JweKeyAlgorithm> AllowedJweKeyAlgorithms { get; internal set; }

        /// <summary>
        /// Gets the set of allowed JWE content encryption algorithms.
        /// </summary>
        public HashSet<JweContentAlgorithm> AllowedJweContentAlgorithms { get; internal set; }

        /// <summary>
        /// Gets whether strict certificate validation is enforced.
        /// </summary>
        public bool StrictCertificateValidation { get; internal set; }

        /// <summary>
        /// Gets the default timeout for cryptographic operations.
        /// </summary>
        public TimeSpan DefaultOperationTimeout { get; internal set; }

        /// <summary>
        /// Gets the maximum number of retry attempts for failed operations.
        /// </summary>
        public int MaxRetryAttempts { get; internal set; }

        /// <summary>
        /// Gets the current logging level.
        /// </summary>
        public LogLevel LogLevel { get; internal set; }

        /// <summary>
        /// Gets whether detailed operational logging is enabled.
        /// </summary>
        public bool EnableDetailedLogging { get; internal set; }

        /// <summary>
        /// Creates a formatted string representation of the configuration.
        /// </summary>
        /// <returns>A multi-line string containing all configuration settings.</returns>
        public override string ToString()
        {
            var lines = new List<string>
            {
                "OpenSLLWrapper Configuration:",
                $"  Cryptographic Settings:",
                $"    Default Key Size: {DefaultKeySize} bits",
                $"    Default JWT Algorithm: {DefaultJwtAlgorithm}",
                $"    Default JWT Expiration: {DefaultJwtExpirationMinutes} minutes",
                $"    Default Clock Skew: {DefaultClockSkewMinutes} minutes",
                $"  Performance Settings:",
                $"    Signer Pool Size: {SignerPoolSize}",
                $"    Signer Caching: {(SignerCachingEnabled ? "Enabled" : "Disabled")}",
                $"    Max Parallelism: {MaxDegreeOfParallelism}",
                $"    Performance Counters: {(EnablePerformanceCounters ? "Enabled" : "Disabled")}",
                $"  Security Policy:",
                $"    Minimum Key Size: {MinimumKeySize} bits",
                $"    Allowed JWT Algorithms: {string.Join(", ", AllowedJwtAlgorithms)}",
                $"    Strict Certificate Validation: {(StrictCertificateValidation ? "Enabled" : "Disabled")}",
                $"  Operational Settings:",
                $"    Operation Timeout: {DefaultOperationTimeout}",
                $"    Max Retry Attempts: {MaxRetryAttempts}",
                $"    Log Level: {LogLevel}",
                $"    Detailed Logging: {(EnableDetailedLogging ? "Enabled" : "Disabled")}"
            };

            return string.Join(Environment.NewLine, lines);
        }
    }

    /// <summary>
    /// Performance metrics and statistics for OpenSLLWrapper operations.
    /// </summary>
    public class PerformanceMetrics
    {
        /// <summary>
        /// Gets or sets the total number of RSA key generation operations performed.
        /// </summary>
        public long KeyGenerationCount { get; set; }

        /// <summary>
        /// Gets or sets the total time spent on RSA key generation operations.
        /// </summary>
        public TimeSpan TotalKeyGenerationTime { get; set; }

        /// <summary>
        /// Gets or sets the total number of signing operations performed.
        /// </summary>
        public long SigningOperationCount { get; set; }

        /// <summary>
        /// Gets or sets the total time spent on signing operations.
        /// </summary>
        public TimeSpan TotalSigningTime { get; set; }

        /// <summary>
        /// Gets or sets the total number of verification operations performed.
        /// </summary>
        public long VerificationOperationCount { get; set; }

        /// <summary>
        /// Gets or sets the total time spent on verification operations.
        /// </summary>
        public TimeSpan TotalVerificationTime { get; set; }

        /// <summary>
        /// Gets or sets the total number of certificate operations performed.
        /// </summary>
        public long CertificateOperationCount { get; set; }

        /// <summary>
        /// Gets or sets the total time spent on certificate operations.
        /// </summary>
        public TimeSpan TotalCertificateTime { get; set; }

        /// <summary>
        /// Gets or sets the total number of JWT operations performed.
        /// </summary>
        public long JwtOperationCount { get; set; }

        /// <summary>
        /// Gets or sets the total time spent on JWT operations.
        /// </summary>
        public TimeSpan TotalJwtTime { get; set; }

        /// <summary>
        /// Gets the average time per key generation operation.
        /// </summary>
        public TimeSpan AverageKeyGenerationTime => 
            KeyGenerationCount > 0 ? TimeSpan.FromTicks(TotalKeyGenerationTime.Ticks / KeyGenerationCount) : TimeSpan.Zero;

        /// <summary>
        /// Gets the average time per signing operation.
        /// </summary>
        public TimeSpan AverageSigningTime => 
            SigningOperationCount > 0 ? TimeSpan.FromTicks(TotalSigningTime.Ticks / SigningOperationCount) : TimeSpan.Zero;

        /// <summary>
        /// Gets the average time per verification operation.
        /// </summary>
        public TimeSpan AverageVerificationTime => 
            VerificationOperationCount > 0 ? TimeSpan.FromTicks(TotalVerificationTime.Ticks / VerificationOperationCount) : TimeSpan.Zero;

        /// <summary>
        /// Gets the average time per certificate operation.
        /// </summary>
        public TimeSpan AverageCertificateTime => 
            CertificateOperationCount > 0 ? TimeSpan.FromTicks(TotalCertificateTime.Ticks / CertificateOperationCount) : TimeSpan.Zero;

        /// <summary>
        /// Gets the average time per JWT operation.
        /// </summary>
        public TimeSpan AverageJwtTime => 
            JwtOperationCount > 0 ? TimeSpan.FromTicks(TotalJwtTime.Ticks / JwtOperationCount) : TimeSpan.Zero;

        /// <summary>
        /// Gets the total number of operations performed across all categories.
        /// </summary>
        public long TotalOperationCount => 
            KeyGenerationCount + SigningOperationCount + VerificationOperationCount + 
            CertificateOperationCount + JwtOperationCount;

        /// <summary>
        /// Gets the total time spent on all operations.
        /// </summary>
        public TimeSpan TotalOperationTime => 
            TotalKeyGenerationTime + TotalSigningTime + TotalVerificationTime + 
            TotalCertificateTime + TotalJwtTime;

        /// <summary>
        /// Resets all performance metrics to zero.
        /// </summary>
        public void Reset()
        {
            KeyGenerationCount = 0;
            TotalKeyGenerationTime = TimeSpan.Zero;
            SigningOperationCount = 0;
            TotalSigningTime = TimeSpan.Zero;
            VerificationOperationCount = 0;
            TotalVerificationTime = TimeSpan.Zero;
            CertificateOperationCount = 0;
            TotalCertificateTime = TimeSpan.Zero;
            JwtOperationCount = 0;
            TotalJwtTime = TimeSpan.Zero;
        }

        /// <summary>
        /// Creates a formatted string representation of the performance metrics.
        /// </summary>
        /// <returns>A multi-line string containing all performance metrics.</returns>
        public override string ToString()
        {
            var lines = new List<string>
            {
                "OpenSLLWrapper Performance Metrics:",
                $"  Key Generation: {KeyGenerationCount:N0} operations, {TotalKeyGenerationTime:g} total, {AverageKeyGenerationTime.TotalMilliseconds:F2}ms average",
                $"  Signing: {SigningOperationCount:N0} operations, {TotalSigningTime:g} total, {AverageSigningTime.TotalMilliseconds:F2}ms average",
                $"  Verification: {VerificationOperationCount:N0} operations, {TotalVerificationTime:g} total, {AverageVerificationTime.TotalMilliseconds:F2}ms average",
                $"  Certificates: {CertificateOperationCount:N0} operations, {TotalCertificateTime:g} total, {AverageCertificateTime.TotalMilliseconds:F2}ms average",
                $"  JWT: {JwtOperationCount:N0} operations, {TotalJwtTime:g} total, {AverageJwtTime.TotalMilliseconds:F2}ms average",
                $"  Total: {TotalOperationCount:N0} operations, {TotalOperationTime:g} total"
            };

            return string.Join(Environment.NewLine, lines);
        }
    }
}