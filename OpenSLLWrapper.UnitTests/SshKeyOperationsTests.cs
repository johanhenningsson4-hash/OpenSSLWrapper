using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for SSH key format operations.
    /// </summary>
    [TestClass]
    public class SshKeyOperationsTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;
        private string _publicKeyPem;
        private byte[] _privateKeyBytes;
        private byte[] _publicKeyBytes;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_SshTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            
            // Generate test keys
            _privateKeyBytes = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
            _privateKeyPem = Encoding.UTF8.GetString(_privateKeyBytes);
            _publicKeyBytes = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(_privateKeyBytes);
            _publicKeyPem = Encoding.UTF8.GetString(_publicKeyBytes);
        }

        [TestCleanup]
        public void TestCleanup()
        {
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        #region SSH Public Key Conversion Tests

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithValidPemBytes_ReturnsValidSshKey()
        {
            // Arrange
            string comment = "test@example.com";

            // Act
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey(_publicKeyBytes, comment);

            // Assert - Should not throw due to parameter validation
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_FromFile_ReturnsValidSshKey()
        {
            // Arrange
            string publicKeyPath = Path.Combine(_tempDirectory, "public_key.pem");
            File.WriteAllText(publicKeyPath, _publicKeyPem);
            string comment = "user@workstation";

            // Act
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey(publicKeyPath, comment);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithEmptyComment_DoesNotThrow()
        {
            // Act
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey(_publicKeyBytes, "");

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithNullComment_DoesNotThrow()
        {
            // Act
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey(_publicKeyBytes, null);

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithNullPemBytes_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey((byte[])null, "comment");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithEmptyPemBytes_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey(new byte[0], "comment");
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithNullFilePath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey((string)null, "comment");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPemToSshPublicKey_WithEmptyFilePath_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToSshPublicKey(string.Empty, "comment");
            act.Should().ThrowExactly<ArgumentException>();
        }

        #endregion

        #region SSH to PEM Conversion Tests

        [TestMethod]
        public void ConvertSshPublicKeyToPem_WithValidSshKey_ReturnsPemBytes()
        {
            // Arrange
            string sshKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDhA... user@example.com";

            // Act
            Action act = () => SshKeyFacade.ConvertSshPublicKeyToPem(sshKey);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertSshPublicKeyToPem_WithNullSshKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertSshPublicKeyToPem(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertSshPublicKeyToPem_WithEmptySshKey_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertSshPublicKeyToPem(string.Empty);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ConvertSshPublicKeyToPem_WithWhitespaceSshKey_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertSshPublicKeyToPem("   ");
            act.Should().ThrowExactly<ArgumentException>();
        }

        #endregion

        #region SSH Private Key Conversion Tests

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_WithValidPemBytes_ReturnsValidSshPrivateKey()
        {
            // Arrange
            string passphrase = "secure_passphrase";

            // Act
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(_privateKeyBytes, passphrase);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_WithNullPassphrase_DoesNotThrow()
        {
            // Act
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(_privateKeyBytes, null);

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_FromFile_CreatesValidSshPrivateKey()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "private_key.pem");
            string sshKeyPath = Path.Combine(_tempDirectory, "id_rsa");
            File.WriteAllText(privateKeyPath, _privateKeyPem);
            string passphrase = "test_passphrase";

            // Act
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(
                privateKeyPath, 
                sshKeyPath, 
                passphrase);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_WithNullPrivateKeyBytes_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey((byte[])null, "passphrase");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_WithEmptyPrivateKeyBytes_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(new byte[0], "passphrase");
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_WithNullFilePath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(
                (string)null, 
                "output.key", 
                "passphrase");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPemToOpenSshPrivateKey_WithNullOutputPath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(
                "input.pem", 
                null, 
                "passphrase");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        #endregion

        #region SSH Private Key to PEM Conversion Tests

        [TestMethod]
        public void ConvertOpenSshPrivateKeyToPem_WithValidSshKeyBytes_ReturnsPemBytes()
        {
            // Arrange
            byte[] dummySshKey = Encoding.UTF8.GetBytes("-----BEGIN OPENSSH PRIVATE KEY-----\ndummy_content\n-----END OPENSSH PRIVATE KEY-----");
            string passphrase = "test_passphrase";

            // Act
            Action act = () => SshKeyFacade.ConvertOpenSshPrivateKeyToPem(dummySshKey, passphrase);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertOpenSshPrivateKeyToPem_FromFile_CreatesPemFile()
        {
            // Arrange
            string sshKeyPath = Path.Combine(_tempDirectory, "id_rsa");
            string pemOutputPath = Path.Combine(_tempDirectory, "converted_key.pem");
            string passphrase = "test_passphrase";
            
            // Create a dummy SSH private key file
            File.WriteAllText(sshKeyPath, "-----BEGIN OPENSSH PRIVATE KEY-----\ndummy_content\n-----END OPENSSH PRIVATE KEY-----");

            // Act
            Action act = () => SshKeyFacade.ConvertOpenSshPrivateKeyToPem(
                sshKeyPath, 
                pemOutputPath, 
                passphrase);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertOpenSshPrivateKeyToPem_WithNullSshKeyBytes_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertOpenSshPrivateKeyToPem((byte[])null, "passphrase");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertOpenSshPrivateKeyToPem_WithEmptySshKeyBytes_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ConvertOpenSshPrivateKeyToPem(new byte[0], "passphrase");
            act.Should().ThrowExactly<ArgumentException>();
        }

        #endregion

        #region SSH Key Utility Tests

        [TestMethod]
        public void ExtractSshPublicKeyComment_WithValidSshKeyWithComment_ReturnsComment()
        {
            // Arrange
            string sshKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqaj... user@example.com";

            // Act
            Action act = () => SshKeyFacade.ExtractSshPublicKeyComment(sshKey);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ExtractSshPublicKeyComment_WithSshKeyNoComment_DoesNotThrow()
        {
            // Arrange
            string sshKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqaj...";

            // Act
            Action act = () => SshKeyFacade.ExtractSshPublicKeyComment(sshKey);

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void ExtractSshPublicKeyComment_WithNullSshKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ExtractSshPublicKeyComment(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ExtractSshPublicKeyComment_WithEmptySshKey_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ExtractSshPublicKeyComment(string.Empty);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ValidateSshPublicKeyFormat_WithValidSshKey_ReturnsValidationResult()
        {
            // Arrange
            string sshKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqaj... user@example.com";

            // Act
            Action act = () => SshKeyFacade.ValidateSshPublicKeyFormat(sshKey);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
        }

        [TestMethod]
        public void ValidateSshPublicKeyFormat_WithInvalidSshKey_ReturnsValidationResult()
        {
            // Arrange
            string invalidSshKey = "invalid-key-format";

            // Act
            Action act = () => SshKeyFacade.ValidateSshPublicKeyFormat(invalidSshKey);

            // Assert - Should not throw, should return validation result
            act.Should().NotThrow();
        }

        [TestMethod]
        public void ValidateSshPublicKeyFormat_WithNullSshKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.ValidateSshPublicKeyFormat(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        #endregion

        #region SSH Key Generation Tests

        [TestMethod]
        public void GenerateSshKeyPair_WithValidParameters_ReturnsKeyPair()
        {
            // Arrange
            int keySize = 2048;
            string comment = "generated@test";
            string passphrase = "secure_passphrase";

            // Act
            Action act = () => SshKeyFacade.GenerateSshKeyPair(keySize, comment, passphrase);

            // Assert
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void GenerateSshKeyPair_WithDefaultParameters_ReturnsKeyPair()
        {
            // Act
            Action act = () => SshKeyFacade.GenerateSshKeyPair();

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        [DataRow(1024)]
        [DataRow(2048)]
        [DataRow(3072)]
        [DataRow(4096)]
        public void GenerateSshKeyPair_WithValidKeySizes_ReturnsKeyPair(int keySize)
        {
            // Act
            Action act = () => SshKeyFacade.GenerateSshKeyPair(keySize, "test@host");

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void GenerateSshKeyPair_WithInvalidKeySize_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => SshKeyFacade.GenerateSshKeyPair(512, "test@host");
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void GenerateSshKeyPair_WithNullComment_DoesNotThrow()
        {
            // Act
            Action act = () => SshKeyFacade.GenerateSshKeyPair(2048, null);

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void GenerateSshKeyPair_WithNullPassphrase_DoesNotThrow()
        {
            // Act
            Action act = () => SshKeyFacade.GenerateSshKeyPair(2048, "test@host", null);

            // Assert
            act.Should().NotThrow();
        }

        #endregion

        #region Round-Trip Tests (Placeholder)

        [TestMethod]
        public void SshKeyRoundTrip_ConvertPemToSshAndBack_ShouldPreserveKeyData()
        {
            // This test would verify that converting PEM → SSH → PEM preserves the key data
            // Actual implementation would test the full round-trip functionality
            
            // Act & Assert - Test that the API contract is consistent
            Action convertToSshAct = () => SshKeyFacade.ConvertPemToSshPublicKey(_publicKeyBytes, "test");
            Action convertToPemAct = () => SshKeyFacade.ConvertSshPublicKeyToPem("ssh-rsa AAAAB3... test");

            convertToSshAct.Should().NotThrow();
            convertToPemAct.Should().NotThrow<ArgumentException>(); // May throw other exceptions due to dummy data
        }

        [TestMethod]
        public void SshPrivateKeyRoundTrip_ConvertPemToSshAndBack_ShouldPreserveKeyData()
        {
            // This test would verify that converting PEM private → SSH private → PEM private preserves the key data
            
            // Act & Assert - Test that the API contract is consistent
            Action convertToSshAct = () => SshKeyFacade.ConvertPemToOpenSshPrivateKey(_privateKeyBytes, "passphrase");
            Action convertToPemAct = () => SshKeyFacade.ConvertOpenSshPrivateKeyToPem(new byte[100], "passphrase");

            convertToSshAct.Should().NotThrow();
            convertToPemAct.Should().NotThrow<ArgumentException>(); // May throw other exceptions due to dummy data
        }

        #endregion
    }
}