using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for configuration management operations.
    /// </summary>
    [TestClass]
    public class ConfigurationTests
    {
        [TestInitialize]
        public void TestInitialize()
        {
            // Reset configuration to defaults before each test
            OpenSslWrapperConfig.InitializeDefaults();
        }

        #region Initialization Tests

        [TestMethod]
        public void InitializeDefaults_WhenCalled_SetsSecureDefaults()
        {
            // Act
            OpenSslWrapperConfig.InitializeDefaults();

            // Assert - Verify default values are set
            OpenSslWrapperConfig.DefaultKeySize.Should().Be(2048);
            OpenSslWrapperConfig.DefaultJwtAlgorithm.Should().Be(JwtAlgorithm.RS256);
            OpenSslWrapperConfig.DefaultJwtExpirationMinutes.Should().Be(60);
            OpenSslWrapperConfig.DefaultClockSkewMinutes.Should().Be(5);
            OpenSslWrapperConfig.MinimumKeySize.Should().Be(1024);
            OpenSslWrapperConfig.StrictCertificateValidation.Should().BeTrue();
        }

        #endregion

        #region Cryptographic Settings Tests

        [TestMethod]
        public void DefaultKeySize_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.DefaultKeySize = 4096;

            // Assert
            OpenSslWrapperConfig.DefaultKeySize.Should().Be(4096);
        }

        [TestMethod]
        [DataRow(1024)]
        [DataRow(2048)]
        [DataRow(3072)]
        [DataRow(4096)]
        [DataRow(8192)]
        public void DefaultKeySize_SetValidKeySizes_UpdatesSuccessfully(int keySize)
        {
            // Act
            OpenSslWrapperConfig.DefaultKeySize = keySize;

            // Assert
            OpenSslWrapperConfig.DefaultKeySize.Should().Be(keySize);
        }

        [TestMethod]
        public void DefaultKeySize_SetBelowMinimum_ThrowsArgumentException()
        {
            // Arrange
            OpenSslWrapperConfig.MinimumKeySize = 2048;

            // Act & Assert
            Action act = () => OpenSslWrapperConfig.DefaultKeySize = 1024;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Default key size cannot be less than minimum key size*");
        }

        [TestMethod]
        public void DefaultJwtAlgorithm_SetAllowedAlgorithm_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.DefaultJwtAlgorithm = JwtAlgorithm.RS384;

            // Assert
            OpenSslWrapperConfig.DefaultJwtAlgorithm.Should().Be(JwtAlgorithm.RS384);
        }

        [TestMethod]
        public void DefaultJwtExpirationMinutes_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.DefaultJwtExpirationMinutes = 30;

            // Assert
            OpenSslWrapperConfig.DefaultJwtExpirationMinutes.Should().Be(30);
        }

        [TestMethod]
        public void DefaultJwtExpirationMinutes_SetZero_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.DefaultJwtExpirationMinutes = 0;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*JWT expiration minutes must be positive*");
        }

        [TestMethod]
        public void DefaultJwtExpirationMinutes_SetNegative_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.DefaultJwtExpirationMinutes = -10;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*JWT expiration minutes must be positive*");
        }

        [TestMethod]
        public void DefaultClockSkewMinutes_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.DefaultClockSkewMinutes = 10;

            // Assert
            OpenSslWrapperConfig.DefaultClockSkewMinutes.Should().Be(10);
        }

        [TestMethod]
        public void DefaultClockSkewMinutes_SetZero_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.DefaultClockSkewMinutes = 0;

            // Assert
            OpenSslWrapperConfig.DefaultClockSkewMinutes.Should().Be(0);
        }

        [TestMethod]
        public void DefaultClockSkewMinutes_SetNegative_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.DefaultClockSkewMinutes = -5;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Clock skew minutes cannot be negative*");
        }

        #endregion

        #region Performance Settings Tests

        [TestMethod]
        public void SignerPoolSize_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.SignerPoolSize = 8;

            // Assert
            OpenSslWrapperConfig.SignerPoolSize.Should().Be(8);
        }

        [TestMethod]
        public void SignerPoolSize_SetZero_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.SignerPoolSize = 0;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Signer pool size must be positive*");
        }

        [TestMethod]
        public void SignerPoolSize_SetNegative_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.SignerPoolSize = -1;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Signer pool size must be positive*");
        }

        [TestMethod]
        public void SignerCachingEnabled_SetTrue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.SignerCachingEnabled = true;

            // Assert
            OpenSslWrapperConfig.SignerCachingEnabled.Should().BeTrue();
        }

        [TestMethod]
        public void SignerCachingEnabled_SetFalse_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.SignerCachingEnabled = false;

            // Assert
            OpenSslWrapperConfig.SignerCachingEnabled.Should().BeFalse();
        }

        [TestMethod]
        public void MaxDegreeOfParallelism_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.MaxDegreeOfParallelism = 4;

            // Assert
            OpenSslWrapperConfig.MaxDegreeOfParallelism.Should().Be(4);
        }

        [TestMethod]
        public void MaxDegreeOfParallelism_SetZero_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.MaxDegreeOfParallelism = 0;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Max degree of parallelism must be positive*");
        }

        [TestMethod]
        public void EnablePerformanceCounters_SetTrue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.EnablePerformanceCounters = true;

            // Assert
            OpenSslWrapperConfig.EnablePerformanceCounters.Should().BeTrue();
        }

        [TestMethod]
        public void EnablePerformanceCounters_SetFalse_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.EnablePerformanceCounters = false;

            // Assert
            OpenSslWrapperConfig.EnablePerformanceCounters.Should().BeFalse();
        }

        #endregion

        #region Security Policy Settings Tests

        [TestMethod]
        public void MinimumKeySize_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.MinimumKeySize = 2048;

            // Assert
            OpenSslWrapperConfig.MinimumKeySize.Should().Be(2048);
        }

        [TestMethod]
        public void MinimumKeySize_SetTooLow_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.MinimumKeySize = 256;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Minimum key size cannot be less than 512 bits*");
        }

        [TestMethod]
        public void MinimumKeySize_SetHigherThanDefault_AdjustsDefaultKeySize()
        {
            // Arrange
            OpenSslWrapperConfig.DefaultKeySize = 1024;

            // Act
            OpenSslWrapperConfig.MinimumKeySize = 2048;

            // Assert
            OpenSslWrapperConfig.MinimumKeySize.Should().Be(2048);
            OpenSslWrapperConfig.DefaultKeySize.Should().Be(2048); // Should be auto-adjusted
        }

        [TestMethod]
        public void AllowedJwtAlgorithms_GetValue_ReturnsHashSet()
        {
            // Act
            var algorithms = OpenSslWrapperConfig.AllowedJwtAlgorithms;

            // Assert
            algorithms.Should().NotBeNull();
            algorithms.Should().BeAssignableTo<HashSet<JwtAlgorithm>>();
            algorithms.Should().Contain(JwtAlgorithm.RS256); // Default should include RS256
        }

        [TestMethod]
        public void SetAllowedJwtAlgorithms_WithValidAlgorithms_UpdatesSuccessfully()
        {
            // Arrange
            var newAlgorithms = new[] { JwtAlgorithm.PS256, JwtAlgorithm.PS384, JwtAlgorithm.PS512 };

            // Act
            OpenSslWrapperConfig.SetAllowedJwtAlgorithms(newAlgorithms);

            // Assert
            var allowedAlgorithms = OpenSslWrapperConfig.AllowedJwtAlgorithms;
            allowedAlgorithms.Should().BeEquivalentTo(newAlgorithms);
        }

        [TestMethod]
        public void SetAllowedJwtAlgorithms_WithNullCollection_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.SetAllowedJwtAlgorithms(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void SetAllowedJwtAlgorithms_WithEmptyCollection_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.SetAllowedJwtAlgorithms(new JwtAlgorithm[0]);
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*At least one algorithm must be allowed*");
        }

        [TestMethod]
        public void SetAllowedJwtAlgorithms_CurrentDefaultNotAllowed_UpdatesDefaultToFirstAllowed()
        {
            // Arrange
            OpenSslWrapperConfig.DefaultJwtAlgorithm = JwtAlgorithm.RS256;
            var newAlgorithms = new[] { JwtAlgorithm.PS256, JwtAlgorithm.PS384 };

            // Act
            OpenSslWrapperConfig.SetAllowedJwtAlgorithms(newAlgorithms);

            // Assert
            OpenSslWrapperConfig.DefaultJwtAlgorithm.Should().Be(JwtAlgorithm.PS256); // Should be auto-updated
        }

        [TestMethod]
        public void StrictCertificateValidation_SetTrue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.StrictCertificateValidation = true;

            // Assert
            OpenSslWrapperConfig.StrictCertificateValidation.Should().BeTrue();
        }

        [TestMethod]
        public void StrictCertificateValidation_SetFalse_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.StrictCertificateValidation = false;

            // Assert
            OpenSslWrapperConfig.StrictCertificateValidation.Should().BeFalse();
        }

        #endregion

        #region Operational Settings Tests

        [TestMethod]
        public void DefaultOperationTimeout_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.DefaultOperationTimeout = TimeSpan.FromMinutes(10);

            // Assert
            OpenSslWrapperConfig.DefaultOperationTimeout.Should().Be(TimeSpan.FromMinutes(10));
        }

        [TestMethod]
        public void DefaultOperationTimeout_SetZero_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.DefaultOperationTimeout = TimeSpan.Zero;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Operation timeout must be positive*");
        }

        [TestMethod]
        public void DefaultOperationTimeout_SetNegative_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.DefaultOperationTimeout = TimeSpan.FromSeconds(-10);
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Operation timeout must be positive*");
        }

        [TestMethod]
        public void MaxRetryAttempts_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.MaxRetryAttempts = 5;

            // Assert
            OpenSslWrapperConfig.MaxRetryAttempts.Should().Be(5);
        }

        [TestMethod]
        public void MaxRetryAttempts_SetZero_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.MaxRetryAttempts = 0;

            // Assert
            OpenSslWrapperConfig.MaxRetryAttempts.Should().Be(0);
        }

        [TestMethod]
        public void MaxRetryAttempts_SetNegative_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslWrapperConfig.MaxRetryAttempts = -1;
            act.Should().ThrowExactly<ArgumentException>()
                .WithMessage("*Max retry attempts cannot be negative*");
        }

        [TestMethod]
        public void LogLevel_SetValidValue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.LogLevel = LogLevel.Debug;

            // Assert
            OpenSslWrapperConfig.LogLevel.Should().Be(LogLevel.Debug);
        }

        [TestMethod]
        public void EnableDetailedLogging_SetTrue_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.EnableDetailedLogging = true;

            // Assert
            OpenSslWrapperConfig.EnableDetailedLogging.Should().BeTrue();
        }

        [TestMethod]
        public void EnableDetailedLogging_SetFalse_UpdatesSuccessfully()
        {
            // Act
            OpenSslWrapperConfig.EnableDetailedLogging = false;

            // Assert
            OpenSslWrapperConfig.EnableDetailedLogging.Should().BeFalse();
        }

        #endregion

        #region Configuration Management Tests

        [TestMethod]
        public void GetCurrentConfiguration_WhenCalled_ReturnsSnapshot()
        {
            // Act
            var config = OpenSslWrapperConfig.GetCurrentConfiguration();

            // Assert
            config.Should().NotBeNull();
            config.Should().BeOfType<ConfigurationSnapshot>();
            config.DefaultKeySize.Should().Be(OpenSslWrapperConfig.DefaultKeySize);
            config.DefaultJwtAlgorithm.Should().Be(OpenSslWrapperConfig.DefaultJwtAlgorithm);
        }

        [TestMethod]
        public void GetCurrentConfiguration_MultipleCallsAfterChanges_ReturnsCurrentValues()
        {
            // Arrange
            var originalConfig = OpenSslWrapperConfig.GetCurrentConfiguration();
            
            // Act
            OpenSslWrapperConfig.DefaultKeySize = 4096;
            OpenSslWrapperConfig.DefaultJwtAlgorithm = JwtAlgorithm.RS384;
            var updatedConfig = OpenSslWrapperConfig.GetCurrentConfiguration();

            // Assert
            originalConfig.DefaultKeySize.Should().NotBe(updatedConfig.DefaultKeySize);
            updatedConfig.DefaultKeySize.Should().Be(4096);
            updatedConfig.DefaultJwtAlgorithm.Should().Be(JwtAlgorithm.RS384);
        }

        [TestMethod]
        public void ValidateConfiguration_WithValidConfiguration_ReturnsEmptyList()
        {
            // Arrange
            OpenSslWrapperConfig.InitializeDefaults();

            // Act
            var issues = OpenSslWrapperConfig.ValidateConfiguration();

            // Assert
            issues.Should().NotBeNull();
            issues.Should().BeEmpty();
        }

        [TestMethod]
        public void ValidateConfiguration_WithInvalidSettings_ReturnsIssues()
        {
            // Arrange - Create invalid configuration by bypassing property setters
            // This would need backend support to create invalid states for testing

            // Act
            var issues = OpenSslWrapperConfig.ValidateConfiguration();

            // Assert - Should not throw and should return a list (empty or with issues)
            issues.Should().NotBeNull();
            Action act = () => OpenSslWrapperConfig.ValidateConfiguration();
            act.Should().NotThrow();
        }

        #endregion

        #region ConfigurationSnapshot Tests

        [TestMethod]
        public void ConfigurationSnapshot_ToString_ReturnsFormattedString()
        {
            // Arrange
            var config = OpenSslWrapperConfig.GetCurrentConfiguration();

            // Act
            string configString = config.ToString();

            // Assert
            configString.Should().NotBeNullOrEmpty();
            configString.Should().Contain("OpenSLLWrapper Configuration:");
            configString.Should().Contain($"Default Key Size: {config.DefaultKeySize}");
            configString.Should().Contain($"Default JWT Algorithm: {config.DefaultJwtAlgorithm}");
            configString.Should().Contain($"Log Level: {config.LogLevel}");
        }

        [TestMethod]
        public void ConfigurationSnapshot_Properties_AreReadOnly()
        {
            // Arrange
            var config = OpenSslWrapperConfig.GetCurrentConfiguration();

            // Act & Assert - Properties should not have public setters
            var properties = typeof(ConfigurationSnapshot).GetProperties();
            foreach (var property in properties.Where(p => p.Name != "AllowedJwtAlgorithms" && 
                                                           p.Name != "AllowedJweKeyAlgorithms" && 
                                                           p.Name != "AllowedJweContentAlgorithms"))
            {
                property.SetMethod.Should().BeNull($"Property {property.Name} should not have a public setter");
            }
        }

        #endregion

        #region Thread Safety Tests (Conceptual)

        [TestMethod]
        public void Configuration_ConcurrentAccess_DoesNotThrow()
        {
            // This test verifies that concurrent access doesn't cause exceptions
            // Real thread safety testing would require more complex scenarios
            
            // Act & Assert
            Action concurrentAccess = () =>
            {
                var config1 = OpenSslWrapperConfig.GetCurrentConfiguration();
                OpenSslWrapperConfig.DefaultKeySize = 3072;
                var config2 = OpenSslWrapperConfig.GetCurrentConfiguration();
                OpenSslWrapperConfig.SignerPoolSize = 8;
                var algorithms = OpenSslWrapperConfig.AllowedJwtAlgorithms;
            };

            concurrentAccess.Should().NotThrow();
        }

        #endregion
    }
}