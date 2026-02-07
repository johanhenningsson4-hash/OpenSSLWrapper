using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for RSA key generation functionality.
    /// </summary>
    [TestClass]
    public class RsaKeyGenerationTests
    {
        private string _tempDirectory;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_UnitTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
        }

        [TestCleanup]
        public void TestCleanup()
        {
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        [TestMethod]
        public void GenerateRsaPrivateKeyBytes_ValidKeySize_ReturnsValidPem()
        {
            // Arrange
            int keySize = 2048;

            // Act
            byte[] pemBytes = OpenSslFacade.GenerateRsaPrivateKeyBytes(keySize);

            // Assert
            pemBytes.Should().NotBeNull();
            pemBytes.Should().NotBeEmpty();
            
            string pemString = Encoding.UTF8.GetString(pemBytes);
            pemString.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
            pemString.Should().EndWith("-----END RSA PRIVATE KEY-----");
        }

        [TestMethod]
        public void GenerateRsaPrivateKey_ToFile_CreatesValidPemFile()
        {
            // Arrange
            string filePath = Path.Combine(_tempDirectory, "test_key.pem");
            int keySize = 2048;

            // Act
            OpenSslFacade.GenerateRsaPrivateKey(filePath, keySize);

            // Assert
            File.Exists(filePath).Should().BeTrue();
            
            string content = File.ReadAllText(filePath);
            content.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
            content.Should().EndWith("-----END RSA PRIVATE KEY-----");
        }

        [TestMethod]
        public void GenerateRsaPrivateKey_ToStream_WritesValidPem()
        {
            // Arrange
            int keySize = 2048;

            // Act
            using (var stream = new MemoryStream())
            {
                OpenSslFacade.GenerateRsaPrivateKey(stream, keySize);
                
                // Assert
                stream.Length.Should().BeGreaterThan(0);
                
                string content = Encoding.UTF8.GetString(stream.ToArray());
                content.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
                content.Should().EndWith("-----END RSA PRIVATE KEY-----");
            }
        }

        [TestMethod]
        [DataRow(1024)]
        [DataRow(2048)]
        [DataRow(3072)]
        [DataRow(4096)]
        public void GenerateRsaPrivateKeyBytes_ValidKeySizes_ReturnsValidPem(int keySize)
        {
            // Act
            byte[] pemBytes = OpenSslFacade.GenerateRsaPrivateKeyBytes(keySize);

            // Assert
            pemBytes.Should().NotBeNull();
            pemBytes.Should().NotBeEmpty();
            
            string pemString = Encoding.UTF8.GetString(pemBytes);
            pemString.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
            pemString.Should().EndWith("-----END RSA PRIVATE KEY-----");
        }

        [TestMethod]
        [DataRow(512)]
        [DataRow(256)]
        [DataRow(8192)]
        public void GenerateRsaPrivateKeyBytes_InvalidKeySizes_ShouldHandleGracefully(int keySize)
        {
            // Act & Assert - Should either work or throw a meaningful exception
            Action act = () => OpenSslFacade.GenerateRsaPrivateKeyBytes(keySize);
            
            // This test documents current behavior - the method should either:
            // 1. Work for these key sizes, or 
            // 2. Throw a clear, meaningful exception
            act.Should().NotThrow<NullReferenceException>();
        }

        [TestMethod]
        public void GenerateRsaPrivateKey_NullFilePath_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.GenerateRsaPrivateKey(null, 2048);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void GenerateRsaPrivateKey_EmptyFilePath_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.GenerateRsaPrivateKey(string.Empty, 2048);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void GenerateRsaPrivateKey_NullStream_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.GenerateRsaPrivateKey((Stream)null, 2048);
            act.Should().ThrowExactly<ArgumentNullException>();
        }
    }
}