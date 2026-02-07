using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for public key operations.
    /// </summary>
    [TestClass]
    public class PublicKeyOperationsTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_UnitTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            
            // Generate a test private key for use in tests
            _privateKeyPem = Encoding.UTF8.GetString(OpenSslFacade.GenerateRsaPrivateKeyBytes(2048));
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
        public void ExportPublicKeyPemFromPrivateKeyBytes_ValidPrivateKey_ReturnsValidPublicKey()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act
            byte[] publicKeyBytes = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(privateKeyBytes);

            // Assert
            publicKeyBytes.Should().NotBeNull();
            publicKeyBytes.Should().NotBeEmpty();
            
            string publicKeyPem = Encoding.UTF8.GetString(publicKeyBytes);
            publicKeyPem.Should().StartWith("-----BEGIN PUBLIC KEY-----");
            publicKeyPem.Should().EndWith("-----END PUBLIC KEY-----");
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKey_ValidPrivateKeyFile_CreatesValidPublicKeyFile()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "private_key.pem");
            string publicKeyPath = Path.Combine(_tempDirectory, "public_key.pem");
            
            File.WriteAllText(privateKeyPath, _privateKeyPem);

            // Act
            OpenSslFacade.ExportPublicKeyPemFromPrivateKey(privateKeyPath, publicKeyPath);

            // Assert
            File.Exists(publicKeyPath).Should().BeTrue();
            
            string publicKeyContent = File.ReadAllText(publicKeyPath);
            publicKeyContent.Should().StartWith("-----BEGIN PUBLIC KEY-----");
            publicKeyContent.Should().EndWith("-----END PUBLIC KEY-----");
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKey_ToStream_WritesValidPublicKey()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            using var privateKeyStream = new MemoryStream(privateKeyBytes);

            // Act
            using var publicKeyStream = new MemoryStream();
            OpenSLLWrapper.ExportPublicKeyPemFromPrivateKey(privateKeyStream, publicKeyStream);

            // Assert
            publicKeyStream.Length.Should().BeGreaterThan(0);
            
            string publicKeyContent = Encoding.UTF8.GetString(publicKeyStream.ToArray());
            publicKeyContent.Should().StartWith("-----BEGIN PUBLIC KEY-----");
            publicKeyContent.Should().EndWith("-----END PUBLIC KEY-----");
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKeyBytes_NullInput_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKeyBytes_EmptyInput_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(new byte[0]);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKeyBytes_InvalidPemData_ThrowsException()
        {
            // Arrange
            byte[] invalidPemData = Encoding.UTF8.GetBytes("This is not a valid PEM");

            // Act & Assert
            Action act = () => OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(invalidPemData);
            act.Should().Throw<Exception>();
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKey_NullFilePath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ExportPublicKeyPemFromPrivateKey(null, "output.pem");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ExportPublicKeyPemFromPrivateKey_NonExistentFile_ThrowsFileNotFoundException()
        {
            // Arrange
            string nonExistentPath = Path.Combine(_tempDirectory, "nonexistent.pem");
            string outputPath = Path.Combine(_tempDirectory, "output.pem");

            // Act & Assert
            Action act = () => OpenSslFacade.ExportPublicKeyPemFromPrivateKey(nonExistentPath, outputPath);
            act.Should().Throw<FileNotFoundException>();
        }
    }
}