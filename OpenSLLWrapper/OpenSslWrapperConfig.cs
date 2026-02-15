using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Global configuration management for OpenSLLWrapper library operations.
    /// Provides centralized control over default settings, performance tuning, security policies, and operational behavior.
    /// </summary>
    /// <remarks>
    /// This class allows applications to configure library-wide settings such as:
    /// - Default cryptographic parameters (key sizes, algorithms, expiration times)
    /// - Performance optimizations (caching, pooling, parallelism)
    /// - Security policies (minimum key sizes, allowed algorithms, validation rules)
    /// - Operational behavior (logging levels, timeout values, retry policies)
    /// All configuration changes affect subsequent operations but do not modify existing objects.
    /// Thread-safe for concurrent access from multiple threads.
    /// </remarks>
    public static class OpenSslWrapperConfig
    {
        private static readonly object _lock = new object();
        private static volatile bool _isInitialized = false;

        // Default cryptographic settings
        private static int _defaultKeySize = 2048;
        private static JwtAlgorithm _defaultJwtAlgorithm = JwtAlgorithm.RS256;
        private static int _defaultJwtExpirationMinutes = 60;
        private static int _defaultClockSkewMinutes = 5;

        // Performance settings
        private static int _signerPoolSize = Environment.ProcessorCount * 2;
        private static bool _signerCachingEnabled = true;
        private static int _maxDegreeOfParallelism = Environment.ProcessorCount;
        private static bool _enablePerformanceCounters = false;

        // Security policy settings
        private static int _minimumKeySize = 1024;
        private static HashSet<JwtAlgorithm> _allowedJwtAlgorithms;
        private static HashSet<JweKeyAlgorithm> _allowedJweKeyAlgorithms;
        private static HashSet<JweContentAlgorithm> _allowedJweContentAlgorithms;
        private static bool _strictCertificateValidation = true;

        // Operational settings
        private static TimeSpan _defaultOperationTimeout = TimeSpan.FromMinutes(5);
        private static int _maxRetryAttempts = 3;
        private static bool _enableDetailedLogging = false;
        private static LogLevel _logLevel = LogLevel.Warning;

        static OpenSslWrapperConfig()
        {
            InitializeDefaults();
        }

        /// <summary>
        /// Initialize configuration with secure default values.
        /// Called automatically on first use, but can be called explicitly to reset to defaults.
        /// </summary>
        /// <example>
        /// <code>
        /// // Reset all configuration to secure defaults
        /// OpenSslWrapperConfig.InitializeDefaults();
        /// </code>
        /// </example>
        public static void InitializeDefaults()
        {
            lock (_lock)
            {
                // Cryptographic defaults
                _defaultKeySize = 2048;
                _defaultJwtAlgorithm = JwtAlgorithm.RS256;
                _defaultJwtExpirationMinutes = 60;
                _defaultClockSkewMinutes = 5;

                // Performance defaults
                _signerPoolSize = Environment.ProcessorCount * 2;
                _signerCachingEnabled = true;
                _maxDegreeOfParallelism = Environment.ProcessorCount;
                _enablePerformanceCounters = false;

                // Security policy defaults
                _minimumKeySize = 1024;
                _allowedJwtAlgorithms = new HashSet<JwtAlgorithm>
                {
                    JwtAlgorithm.RS256, JwtAlgorithm.RS384, JwtAlgorithm.RS512,
                    JwtAlgorithm.PS256, JwtAlgorithm.PS384, JwtAlgorithm.PS512
                };
                _allowedJweKeyAlgorithms = new HashSet<JweKeyAlgorithm>
                {
                    JweKeyAlgorithm.RsaOaep, JweKeyAlgorithm.RsaOaep256
                };
                _allowedJweContentAlgorithms = new HashSet<JweContentAlgorithm>
                {
                    JweContentAlgorithm.A128Gcm, JweContentAlgorithm.A192Gcm, JweContentAlgorithm.A256Gcm
                };
                _strictCertificateValidation = true;

                // Operational defaults
                _defaultOperationTimeout = TimeSpan.FromMinutes(5);
                _maxRetryAttempts = 3;
                _enableDetailedLogging = false;
                _logLevel = LogLevel.Warning;

                _isInitialized = true;
            }
        }

        #region Cryptographic Settings

        /// <summary>
        /// Gets or sets the default RSA key size in bits for key generation operations.
        /// </summary>
        /// <value>The default key size in bits. Must be at least 1024. Default is 2048.</value>
        /// <exception cref="ArgumentException">Thrown when value is less than the minimum key size.</exception>
        /// <example>
        /// <code>
        /// // Set default key size to 4096 bits for higher security
        /// OpenSslWrapperConfig.DefaultKeySize = 4096;
        /// 
        /// // All subsequent key generation will use 4096 bits by default
        /// byte[] key = OpenSslFacade.GenerateRsaPrivateKeyBytes(); // Uses 4096 bits
        /// </code>
        /// </example>
        public static int DefaultKeySize
        {
            get => _defaultKeySize;
            set
            {
                if (value < _minimumKeySize)
                    throw new ArgumentException($"Default key size cannot be less than minimum key size ({_minimumKeySize}).", nameof(value));
                
                lock (_lock)
                {
                    _defaultKeySize = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the default JWT signing algorithm for JWT operations.
        /// </summary>
        /// <value>The default JWT algorithm. Must be in the allowed algorithms list. Default is RS256.</value>
        /// <exception cref="ArgumentException">Thrown when the algorithm is not in the allowed algorithms list.</exception>
        /// <example>
        /// <code>
        /// // Set default JWT algorithm to PS256 for better security
        /// OpenSslWrapperConfig.DefaultJwtAlgorithm = JwtAlgorithm.PS256;
        /// 
        /// // All subsequent JWT creation will use PS256 by default
        /// string jwt = JoseFacade.CreateJwt(payload, privateKey); // Uses PS256
        /// </code>
        /// </example>
        public static JwtAlgorithm DefaultJwtAlgorithm
        {
            get => _defaultJwtAlgorithm;
            set
            {
                if (!_allowedJwtAlgorithms.Contains(value))
                    throw new ArgumentException($"Algorithm {value} is not in the allowed algorithms list.", nameof(value));
                
                lock (_lock)
                {
                    _defaultJwtAlgorithm = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the default JWT expiration time in minutes.
        /// </summary>
        /// <value>The default expiration time in minutes. Must be positive. Default is 60 minutes.</value>
        /// <exception cref="ArgumentException">Thrown when value is not positive.</exception>
        /// <example>
        /// <code>
        /// // Set default JWT expiration to 30 minutes for short-lived tokens
        /// OpenSslWrapperConfig.DefaultJwtExpirationMinutes = 30;
        /// 
        /// // All subsequent JWTs will expire in 30 minutes by default
        /// string jwt = JoseFacade.CreateJwt(payload, privateKey); // Expires in 30 minutes
        /// </code>
        /// </example>
        public static int DefaultJwtExpirationMinutes
        {
            get => _defaultJwtExpirationMinutes;
            set
            {
                if (value <= 0)
                    throw new ArgumentException("JWT expiration minutes must be positive.", nameof(value));
                
                lock (_lock)
                {
                    _defaultJwtExpirationMinutes = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the default clock skew tolerance in minutes for JWT validation.
        /// </summary>
        /// <value>The clock skew tolerance in minutes. Must be non-negative. Default is 5 minutes.</value>
        /// <exception cref="ArgumentException">Thrown when value is negative.</exception>
        /// <example>
        /// <code>
        /// // Allow 10 minutes clock skew for distributed systems
        /// OpenSslWrapperConfig.DefaultClockSkewMinutes = 10;
        /// 
        /// // JWT validation will be more tolerant of timing differences
        /// var result = JoseFacade.VerifyJwt(jwt, publicKey); // Uses 10 minute tolerance
        /// </code>
        /// </example>
        public static int DefaultClockSkewMinutes
        {
            get => _defaultClockSkewMinutes;
            set
            {
                if (value < 0)
                    throw new ArgumentException("Clock skew minutes cannot be negative.", nameof(value));
                
                lock (_lock)
                {
                    _defaultClockSkewMinutes = value;
                }
            }
        }

        #endregion

        #region Performance Settings

        /// <summary>
        /// Gets or sets the size of the cryptographic signer pool for performance optimization.
        /// </summary>
        /// <value>The number of signers to pool. Must be positive. Default is 2 * ProcessorCount.</value>
        /// <exception cref="ArgumentException">Thrown when value is not positive.</exception>
        /// <example>
        /// <code>
        /// // Increase signer pool for high-throughput scenarios
        /// OpenSslWrapperConfig.SignerPoolSize = 16;
        /// 
        /// // This improves performance for concurrent signing operations
        /// </code>
        /// </example>
        public static int SignerPoolSize
        {
            get => _signerPoolSize;
            set
            {
                if (value <= 0)
                    throw new ArgumentException("Signer pool size must be positive.", nameof(value));
                
                lock (_lock)
                {
                    _signerPoolSize = value;
                    // Notify the backend to resize the pool
                    OpenSLLWrapper.ConfigureSignerPool(value, _signerCachingEnabled);
                }
            }
        }

        /// <summary>
        /// Gets or sets whether signer caching is enabled for performance optimization.
        /// </summary>
        /// <value>True to enable signer caching, false to disable. Default is true.</value>
        /// <example>
        /// <code>
        /// // Disable signer caching for memory-constrained environments
        /// OpenSslWrapperConfig.SignerCachingEnabled = false;
        /// 
        /// // This reduces memory usage but may impact performance
        /// </code>
        /// </example>
        public static bool SignerCachingEnabled
        {
            get => _signerCachingEnabled;
            set
            {
                lock (_lock)
                {
                    _signerCachingEnabled = value;
                    // Notify the backend to update caching behavior
                    OpenSLLWrapper.ConfigureSignerPool(_signerPoolSize, value);
                }
            }
        }

        /// <summary>
        /// Gets or sets the maximum degree of parallelism for batch operations.
        /// </summary>
        /// <value>The maximum number of parallel operations. Must be positive. Default is ProcessorCount.</value>
        /// <exception cref="ArgumentException">Thrown when value is not positive.</exception>
        /// <example>
        /// <code>
        /// // Limit parallelism to avoid resource exhaustion
        /// OpenSslWrapperConfig.MaxDegreeOfParallelism = 4;
        /// 
        /// // Batch operations will use at most 4 parallel threads
        /// </code>
        /// </example>
        public static int MaxDegreeOfParallelism
        {
            get => _maxDegreeOfParallelism;
            set
            {
                if (value <= 0)
                    throw new ArgumentException("Max degree of parallelism must be positive.", nameof(value));
                
                lock (_lock)
                {
                    _maxDegreeOfParallelism = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets whether performance counters are enabled for monitoring.
        /// </summary>
        /// <value>True to enable performance counters, false to disable. Default is false.</value>
        /// <example>
        /// <code>
        /// // Enable performance counters for production monitoring
        /// OpenSslWrapperConfig.EnablePerformanceCounters = true;
        /// 
        /// // Performance metrics will be collected and available for monitoring
        /// </code>
        /// </example>
        public static bool EnablePerformanceCounters
        {
            get => _enablePerformanceCounters;
            set
            {
                lock (_lock)
                {
                    _enablePerformanceCounters = value;
                    // Notify the backend to enable/disable performance monitoring
                    OpenSLLWrapper.ConfigurePerformanceCounters(value);
                }
            }
        }

        #endregion

        #region Security Policy Settings

        /// <summary>
        /// Gets or sets the minimum allowed RSA key size in bits for security policy enforcement.
        /// </summary>
        /// <value>The minimum key size in bits. Must be at least 512. Default is 1024.</value>
        /// <exception cref="ArgumentException">Thrown when value is less than 512.</exception>
        /// <example>
        /// <code>
        /// // Enforce minimum 2048-bit keys for high security
        /// OpenSslWrapperConfig.MinimumKeySize = 2048;
        /// 
        /// // Any attempt to use smaller keys will throw an exception
        /// </code>
        /// </example>
        public static int MinimumKeySize
        {
            get => _minimumKeySize;
            set
            {
                if (value < 512)
                    throw new ArgumentException("Minimum key size cannot be less than 512 bits.", nameof(value));
                
                lock (_lock)
                {
                    _minimumKeySize = value;
                    
                    // Ensure default key size meets minimum requirement
                    if (_defaultKeySize < value)
                        _defaultKeySize = value;
                }
            }
        }

        /// <summary>
        /// Gets a copy of the currently allowed JWT signing algorithms.
        /// Use <see cref="SetAllowedJwtAlgorithms"/> to modify the allowed algorithms.
        /// </summary>
        /// <value>A hash set containing the allowed JWT algorithms.</value>
        /// <example>
        /// <code>
        /// // Check which JWT algorithms are currently allowed
        /// var allowed = OpenSslWrapperConfig.AllowedJwtAlgorithms;
        /// Console.WriteLine($"Allowed algorithms: {string.Join(", ", allowed)}");
        /// </code>
        /// </example>
        public static HashSet<JwtAlgorithm> AllowedJwtAlgorithms
        {
            get
            {
                lock (_lock)
                {
                    return new HashSet<JwtAlgorithm>(_allowedJwtAlgorithms);
                }
            }
        }

        /// <summary>
        /// Set the allowed JWT signing algorithms for security policy enforcement.
        /// </summary>
        /// <param name="algorithms">The algorithms to allow. Must not be null or empty.</param>
        /// <exception cref="ArgumentNullException">Thrown when algorithms is null.</exception>
        /// <exception cref="ArgumentException">Thrown when algorithms is empty.</exception>
        /// <example>
        /// <code>
        /// // Only allow PSS algorithms for maximum security
        /// OpenSslWrapperConfig.SetAllowedJwtAlgorithms(new[] {
        ///     JwtAlgorithm.PS256,
        ///     JwtAlgorithm.PS384,
        ///     JwtAlgorithm.PS512
        /// });
        /// </code>
        /// </example>
        public static void SetAllowedJwtAlgorithms(IEnumerable<JwtAlgorithm> algorithms)
        {
            if (algorithms == null) throw new ArgumentNullException(nameof(algorithms));
            
            var algorithmSet = new HashSet<JwtAlgorithm>(algorithms);
            if (algorithmSet.Count == 0)
                throw new ArgumentException("At least one algorithm must be allowed.", nameof(algorithms));
            
            lock (_lock)
            {
                _allowedJwtAlgorithms = algorithmSet;
                
                // If current default is not allowed, reset to first allowed algorithm
                if (!_allowedJwtAlgorithms.Contains(_defaultJwtAlgorithm))
                {
                    _defaultJwtAlgorithm = _allowedJwtAlgorithms.First();
                }
            }
        }

        /// <summary>
        /// Gets or sets whether strict certificate validation is enforced.
        /// </summary>
        /// <value>True to enforce strict validation, false to allow relaxed validation. Default is true.</value>
        /// <example>
        /// <code>
        /// // Allow self-signed certificates in development
        /// OpenSslWrapperConfig.StrictCertificateValidation = false;
        /// 
        /// // Certificate validation will be more permissive
        /// </code>
        /// </example>
        public static bool StrictCertificateValidation
        {
            get => _strictCertificateValidation;
            set
            {
                lock (_lock)
                {
                    _strictCertificateValidation = value;
                }
            }
        }

        #endregion

        #region Operational Settings

        /// <summary>
        /// Gets or sets the default timeout for cryptographic operations.
        /// </summary>
        /// <value>The operation timeout. Must be positive. Default is 5 minutes.</value>
        /// <exception cref="ArgumentException">Thrown when value is not positive.</exception>
        /// <example>
        /// <code>
        /// // Set shorter timeout for responsive applications
        /// OpenSslWrapperConfig.DefaultOperationTimeout = TimeSpan.FromSeconds(30);
        /// 
        /// // Operations will timeout after 30 seconds instead of 5 minutes
        /// </code>
        /// </example>
        public static TimeSpan DefaultOperationTimeout
        {
            get => _defaultOperationTimeout;
            set
            {
                if (value <= TimeSpan.Zero)
                    throw new ArgumentException("Operation timeout must be positive.", nameof(value));
                
                lock (_lock)
                {
                    _defaultOperationTimeout = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the maximum number of retry attempts for failed operations.
        /// </summary>
        /// <value>The maximum retry attempts. Must be non-negative. Default is 3.</value>
        /// <exception cref="ArgumentException">Thrown when value is negative.</exception>
        /// <example>
        /// <code>
        /// // Disable retries for fail-fast behavior
        /// OpenSslWrapperConfig.MaxRetryAttempts = 0;
        /// 
        /// // Operations will not be retried on failure
        /// </code>
        /// </example>
        public static int MaxRetryAttempts
        {
            get => _maxRetryAttempts;
            set
            {
                if (value < 0)
                    throw new ArgumentException("Max retry attempts cannot be negative.", nameof(value));
                
                lock (_lock)
                {
                    _maxRetryAttempts = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the logging level for library operations.
        /// </summary>
        /// <value>The log level. Default is Warning.</value>
        /// <example>
        /// <code>
        /// // Enable detailed logging for debugging
        /// OpenSslWrapperConfig.LogLevel = LogLevel.Debug;
        /// 
        /// // All debug information will be logged
        /// </code>
        /// </example>
        public static LogLevel LogLevel
        {
            get => _logLevel;
            set
            {
                lock (_lock)
                {
                    _logLevel = value;
                    // Notify the backend logging system
                    OpenSLLWrapper.ConfigureLogging(value, _enableDetailedLogging);
                }
            }
        }

        /// <summary>
        /// Gets or sets whether detailed operational logging is enabled.
        /// </summary>
        /// <value>True to enable detailed logging, false for standard logging. Default is false.</value>
        /// <example>
        /// <code>
        /// // Enable detailed logging for troubleshooting
        /// OpenSslWrapperConfig.EnableDetailedLogging = true;
        /// 
        /// // Additional diagnostic information will be logged
        /// </code>
        /// </example>
        public static bool EnableDetailedLogging
        {
            get => _enableDetailedLogging;
            set
            {
                lock (_lock)
                {
                    _enableDetailedLogging = value;
                    // Notify the backend logging system
                    OpenSLLWrapper.ConfigureLogging(_logLevel, value);
                }
            }
        }

        #endregion

        #region Configuration Management

        /// <summary>
        /// Get the current configuration as a read-only snapshot.
        /// </summary>
        /// <returns>A ConfigurationSnapshot containing all current settings.</returns>
        /// <example>
        /// <code>
        /// // Get current configuration for diagnostics
        /// var config = OpenSslWrapperConfig.GetCurrentConfiguration();
        /// Console.WriteLine($"Default key size: {config.DefaultKeySize}");
        /// Console.WriteLine($"Signer pool size: {config.SignerPoolSize}");
        /// Console.WriteLine($"Log level: {config.LogLevel}");
        /// </code>
        /// </example>
        public static ConfigurationSnapshot GetCurrentConfiguration()
        {
            lock (_lock)
            {
                return new ConfigurationSnapshot
                {
                    DefaultKeySize = _defaultKeySize,
                    DefaultJwtAlgorithm = _defaultJwtAlgorithm,
                    DefaultJwtExpirationMinutes = _defaultJwtExpirationMinutes,
                    DefaultClockSkewMinutes = _defaultClockSkewMinutes,
                    SignerPoolSize = _signerPoolSize,
                    SignerCachingEnabled = _signerCachingEnabled,
                    MaxDegreeOfParallelism = _maxDegreeOfParallelism,
                    EnablePerformanceCounters = _enablePerformanceCounters,
                    MinimumKeySize = _minimumKeySize,
                    AllowedJwtAlgorithms = new HashSet<JwtAlgorithm>(_allowedJwtAlgorithms),
                    AllowedJweKeyAlgorithms = new HashSet<JweKeyAlgorithm>(_allowedJweKeyAlgorithms),
                    AllowedJweContentAlgorithms = new HashSet<JweContentAlgorithm>(_allowedJweContentAlgorithms),
                    StrictCertificateValidation = _strictCertificateValidation,
                    DefaultOperationTimeout = _defaultOperationTimeout,
                    MaxRetryAttempts = _maxRetryAttempts,
                    LogLevel = _logLevel,
                    EnableDetailedLogging = _enableDetailedLogging
                };
            }
        }

        /// <summary>
        /// Validate the current configuration and return any issues found.
        /// </summary>
        /// <returns>A list of configuration validation issues, or empty list if configuration is valid.</returns>
        /// <example>
        /// <code>
        /// // Check for configuration problems
        /// var issues = OpenSslWrapperConfig.ValidateConfiguration();
        /// if (issues.Count > 0)
        /// {
        ///     Console.WriteLine("Configuration issues found:");
        ///     foreach (var issue in issues)
        ///     {
        ///         Console.WriteLine($"- {issue}");
        ///     }
        /// }
        /// </code>
        /// </example>
        public static List<string> ValidateConfiguration()
        {
            var issues = new List<string>();
            
            lock (_lock)
            {
                if (_defaultKeySize < _minimumKeySize)
                    issues.Add($"Default key size ({_defaultKeySize}) is less than minimum key size ({_minimumKeySize})");
                
                if (!_allowedJwtAlgorithms.Contains(_defaultJwtAlgorithm))
                    issues.Add($"Default JWT algorithm ({_defaultJwtAlgorithm}) is not in allowed algorithms list");
                
                if (_defaultJwtExpirationMinutes <= 0)
                    issues.Add($"Default JWT expiration minutes ({_defaultJwtExpirationMinutes}) must be positive");
                
                if (_defaultClockSkewMinutes < 0)
                    issues.Add($"Default clock skew minutes ({_defaultClockSkewMinutes}) cannot be negative");
                
                if (_signerPoolSize <= 0)
                    issues.Add($"Signer pool size ({_signerPoolSize}) must be positive");
                
                if (_maxDegreeOfParallelism <= 0)
                    issues.Add($"Max degree of parallelism ({_maxDegreeOfParallelism}) must be positive");
                
                if (_defaultOperationTimeout <= TimeSpan.Zero)
                    issues.Add($"Default operation timeout ({_defaultOperationTimeout}) must be positive");
                
                if (_maxRetryAttempts < 0)
                    issues.Add($"Max retry attempts ({_maxRetryAttempts}) cannot be negative");
            }
            
            return issues;
        }

        #endregion
    }
}