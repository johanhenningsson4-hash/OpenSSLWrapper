using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for signing and verification operations.
    /// </summary>
    [TestClass]
    public class SigningAndVerificationTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;
        private string _publicKeyPem;
        private string _testMessage;
        private string _testMessageBase64;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_UnitTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            
            // Generate test keys
            _privateKeyPem = Encoding.UTF8.GetString(OpenSslFacade.GenerateRsaPrivateKeyBytes(2048));
            _publicKeyPem = Encoding.UTF8.GetString(OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(Encoding.UTF8.GetBytes(_privateKeyPem)));
            
            _testMessage = "Hello, World! This is a test message for signing.";
            _testMessageBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_testMessage));
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
        public void SignBase64Challenge_ValidInput_ReturnsValidSignature()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "private_key.pem");
            File.WriteAllText(privateKeyPath, _privateKeyPem);

            // Act
            string signature = OpenSslFacade.SignBase64Challenge(_testMessageBase64, privateKeyPath);

            // Assert
            signature.Should().NotBeNullOrWhiteSpace();
            signature.Should().MatchRegex(@"^[A-Za-z0-9+/]+=*$"); // Valid base64 pattern
        }

        [TestMethod]
        public void SignBase64Challenge_WithBytes_ReturnsValidSignature()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act
            byte[] messageBytes = Convert.FromBase64String(_testMessageBase64);
            string signature = OpenSLLWrapper.SignChallengeData(messageBytes, privateKeyBytes);

            // Assert
            signature.Should().NotBeNullOrWhiteSpace();
            signature.Should().MatchRegex(@"^[A-Za-z0-9+/]+=*$");
        }

        [TestMethod]
        public void VerifyBase64Signature_ValidSignature_ReturnsTrue()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "private_key.pem");
            string publicKeyPath = Path.Combine(_tempDirectory, "public_key.pem");
            File.WriteAllText(privateKeyPath, _privateKeyPem);
            File.WriteAllText(publicKeyPath, _publicKeyPem);
            
            string signature = OpenSslFacade.SignBase64Challenge(_testMessageBase64, privateKeyPath);

            // Act
            bool isValid = OpenSLLWrapper.VerifyBase64Signature(_testMessageBase64, signature, publicKeyPath);

            // Assert
            isValid.Should().BeTrue();
        }

        [TestMethod]
        public void VerifyBase64Signature_WithBytes_ValidSignature_ReturnsTrue()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(_publicKeyPem);
            
            string signature = OpenSslFacade.SignBase64Challenge(_testMessageBase64, privateKeyBytes);

            // Act
            byte[] messageBytes = Convert.FromBase64String(_testMessageBase64);
            byte[] signatureBytes = Convert.FromBase64String(signature);
            bool isValid = OpenSLLWrapper.VerifyChallengeData(messageBytes, signatureBytes, publicKeyBytes);

            // Assert
            isValid.Should().BeTrue();
        }

        [TestMethod]
        public void VerifyBase64Signature_TamperedMessage_ReturnsFalse()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(_publicKeyPem);
            
            byte[] messageBytes = Convert.FromBase64String(_testMessageBase64);
            string signature = OpenSLLWrapper.SignChallengeData(messageBytes, privateKeyBytes);
            
            byte[] tamperedMessageBytes = Encoding.UTF8.GetBytes("Tampered message");

            // Act
            byte[] signatureBytes = Convert.FromBase64String(signature);
            bool isValid = OpenSLLWrapper.VerifyChallengeData(tamperedMessageBytes, signatureBytes, publicKeyBytes);

            // Assert
            isValid.Should().BeFalse();
        }

        [TestMethod]
        public void VerifyBase64Signature_TamperedSignature_ReturnsFalse()
        {
            // Arrange
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(_publicKeyPem);
            string tamperedSignature = "VGFtcGVyZWRTaWduYXR1cmU="; // "TamperedSignature" in base64

            // Act
            byte[] messageBytes = Convert.FromBase64String(_testMessageBase64);
            byte[] tamperedSigBytes = Convert.FromBase64String(tamperedSignature);
            bool isValid = OpenSLLWrapper.VerifyChallengeData(messageBytes, tamperedSigBytes, publicKeyBytes);

            // Assert
            isValid.Should().BeFalse();
        }

        [TestMethod]
        public void SignBase64Challenge_NullChallenge_ThrowsArgumentNullException()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act & Assert
            Action act = () => OpenSslFacade.SignBase64Challenge(null, privateKeyBytes);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void SignBase64Challenge_NullPrivateKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => OpenSslFacade.SignBase64Challenge(_testMessageBase64, (byte[])null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void VerifyBase64Signature_NullMessage_ThrowsArgumentNullException()
        {
            // Arrange
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(_publicKeyPem);

            // Act & Assert
            Action act = () => OpenSLLWrapper.VerifyBase64Signature(null, "signature", publicKeyBytes);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void SignAndVerify_RoundTrip_Multiple_Messages_AllValid()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(_publicKeyPem);
            
            string[] testMessages = {
                "Short message",
                "A much longer message that contains various characters: !@#$%^&*()_+-=[]{}|;':\",./<>?",
                "Unicode message: ??????? ?? ραινσϊ",
                "",
                "Message with\nnewlines\r\nand\ttabs"
            };

            // Act & Assert
            foreach (string message in testMessages)
            {
                string messageBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
                string signature = OpenSslFacade.SignBase64Challenge(messageBase64, privateKeyBytes);
                bool isValid = OpenSLLWrapper.VerifyBase64Signature(messageBase64, signature, publicKeyBytes);
                
                isValid.Should().BeTrue($"Failed to verify signature for message: '{message}'");
            }
        }
    }
}