using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for PKCS format conversion operations.
    /// </summary>
    [TestClass]
    public class PkcsConversionTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_UnitTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            
            // Generate a test private key (PKCS#1 format)
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
        public void ConvertPkcs1ToPkcs8Pem_ValidPkcs1Key_ReturnsValidPkcs8()
        {
            // Arrange
            string pkcs1Path = Path.Combine(_tempDirectory, "pkcs1_key.pem");
            string pkcs8Path = Path.Combine(_tempDirectory, "pkcs8_key.pem");
            File.WriteAllText(pkcs1Path, _privateKeyPem);

            // Act
            OpenSslFacade.ConvertPkcs1ToPkcs8Pem(pkcs1Path, pkcs8Path);

            // Assert
            File.Exists(pkcs8Path).Should().BeTrue();
            
            string pkcs8Content = File.ReadAllText(pkcs8Path);
            pkcs8Content.Should().StartWith("-----BEGIN PRIVATE KEY-----");
            pkcs8Content.Should().EndWith("-----END PRIVATE KEY-----");
        }

        [TestMethod]
        public void ConvertPkcs1ToPkcs8Bytes_ValidPkcs1Key_ReturnsValidPkcs8()
        {
            // Arrange
            byte[] pkcs1Bytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act
            byte[] pkcs8Bytes = OpenSslFacade.ConvertPkcs1ToPkcs8PemBytes(pkcs1Bytes);

            // Assert
            pkcs8Bytes.Should().NotBeNull();
            pkcs8Bytes.Should().NotBeEmpty();
            
            string pkcs8Content = Encoding.UTF8.GetString(pkcs8Bytes);
            pkcs8Content.Should().StartWith("-----BEGIN PRIVATE KEY-----");
            pkcs8Content.Should().EndWith("-----END PRIVATE KEY-----");
        }

        [TestMethod]
        public void ConvertPkcs8ToPkcs1Pem_ValidPkcs8Key_ReturnsValidPkcs1()
        {
            // Arrange
            string pkcs1Path = Path.Combine(_tempDirectory, "pkcs1_key.pem");
            string pkcs8Path = Path.Combine(_tempDirectory, "pkcs8_key.pem");
            string roundTripPath = Path.Combine(_tempDirectory, "roundtrip_key.pem");
            
            File.WriteAllText(pkcs1Path, _privateKeyPem);
            OpenSslFacade.ConvertPkcs1ToPkcs8Pem(pkcs1Path, pkcs8Path);

            // Act
            OpenSslFacade.ConvertPkcs8ToPkcs1Pem(pkcs8Path, roundTripPath);

            // Assert
            File.Exists(roundTripPath).Should().BeTrue();
            
            string roundTripContent = File.ReadAllText(roundTripPath);
            roundTripContent.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
            roundTripContent.Should().EndWith("-----END RSA PRIVATE KEY-----");
        }

        [TestMethod]
        public void ConvertPkcs8ToPkcs1Bytes_ValidPkcs8Key_ReturnsValidPkcs1()
        {
            // Arrange
            byte[] pkcs1Bytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            byte[] pkcs8Bytes = OpenSslFacade.ConvertPkcs1ToPkcs8Bytes(pkcs1Bytes);

            // Act
            byte[] roundTripBytes = OpenSslFacade.ConvertPkcs8ToPkcs1Bytes(pkcs8Bytes);

            // Assert
            roundTripBytes.Should().NotBeNull();
            roundTripBytes.Should().NotBeEmpty();
            
            string roundTripContent = Encoding.UTF8.GetString(roundTripBytes);
            roundTripContent.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
            roundTripContent.Should().EndWith("-----END RSA PRIVATE KEY-----");
        }

        [TestMethod]
        public void PkcsConversion_RoundTrip_PreservesKeyFunctionality()
        {
            // Arrange
            byte[] originalPkcs1 = Encoding.UTF8.GetBytes(_privateKeyPem);
            string testMessage = Convert.ToBase64String(Encoding.UTF8.GetBytes("Test message for round trip"));

            // Convert PKCS#1 ? PKCS#8 ? PKCS#1
            byte[] pkcs8Bytes = OpenSslFacade.ConvertPkcs1ToPkcs8PemBytes(originalPkcs1);
            byte[] roundTripPkcs1 = OpenSslFacade.ConvertPkcs8ToPkcs1PemBytes(pkcs8Bytes);

            // Act - Sign with round-trip key
            byte[] messageBytes = Convert.FromBase64String(testMessage);
            string signature = OpenSLLWrapper.SignChallengeData(messageBytes, roundTripPkcs1);

            // Extract public key from original key for verification
            byte[] publicKey = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(originalPkcs1);
            bool isValid = OpenSLLWrapper.VerifyBase64Signature(testMessage, signature, publicKey);

            // Assert
            isValid.Should().BeTrue("Round-trip converted key should still be functional for signing");
        }

        [TestMethod]
        public void ConvertPkcs1ToPkcs8Bytes_NullInput_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ConvertPkcs1ToPkcs8Bytes(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPkcs1ToPkcs8Bytes_EmptyInput_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ConvertPkcs1ToPkcs8Bytes(new byte[0]);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPkcs8ToPkcs1Bytes_NullInput_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ConvertPkcs8ToPkcs1Bytes(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPkcs1ToPkcs8Pem_NullFilePath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.ConvertPkcs1ToPkcs8Pem(null, "output.pem");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPkcs1ToPkcs8Pem_NonExistentFile_ThrowsFileNotFoundException()
        {
            // Arrange
            string nonExistentPath = Path.Combine(_tempDirectory, "nonexistent.pem");
            string outputPath = Path.Combine(_tempDirectory, "output.pem");

            // Act & Assert
            Action act = () => OpenSslFacade.ConvertPkcs1ToPkcs8Pem(nonExistentPath, outputPath);
            act.Should().Throw<FileNotFoundException>();
        }
    }
}