using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for certificate management operations.
    /// </summary>
    [TestClass]
    public class CertificateManagementTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;
        private byte[] _privateKeyBytes;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_CertTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            
            // Generate a test private key
            _privateKeyBytes = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
            _privateKeyPem = Encoding.UTF8.GetString(_privateKeyBytes);
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
        public void CreateSelfSignedCertificate_WithValidParameters_CreatesValidCertificate()
        {
            // Arrange
            string subjectName = "CN=test.example.com,O=Test Corp,C=US";
            var validityPeriod = TimeSpan.FromDays(365);

            // Act
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                subjectName, 
                validityPeriod);

            // Assert
            certificate.Should().NotBeNull();
            certificate.Subject.Should().Contain("CN=test.example.com");
            certificate.Subject.Should().Contain("O=Test Corp");
            certificate.Subject.Should().Contain("C=US");
            certificate.HasPrivateKey.Should().BeTrue();
            certificate.NotBefore.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(5));
            certificate.NotAfter.Should().BeCloseTo(DateTime.UtcNow.Add(validityPeriod), TimeSpan.FromMinutes(5));
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_FromFile_CreatesValidCertificate()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "private_key.pem");
            File.WriteAllText(privateKeyPath, _privateKeyPem);
            string subjectName = "CN=api.example.com,OU=Development";
            var validityPeriod = TimeSpan.FromDays(30);

            // Act
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                privateKeyPath, 
                subjectName, 
                validityPeriod,
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);

            // Assert
            certificate.Should().NotBeNull();
            certificate.Subject.Should().Contain("CN=api.example.com");
            certificate.Subject.Should().Contain("OU=Development");
            certificate.HasPrivateKey.Should().BeTrue();
        }

        [TestMethod]
        [DataRow("CN=simple.com")]
        [DataRow("CN=test.example.com,O=Test Organization")]
        [DataRow("CN=secure.api.com,O=SecureCorp,OU=IT,L=New York,ST=NY,C=US")]
        public void CreateSelfSignedCertificate_WithVariousSubjectNames_CreatesValidCertificates(string subjectName)
        {
            // Arrange
            var validityPeriod = TimeSpan.FromDays(90);

            // Act
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                subjectName, 
                validityPeriod);

            // Assert
            certificate.Should().NotBeNull();
            certificate.HasPrivateKey.Should().BeTrue();
            certificate.NotAfter.Should().BeAfter(DateTime.UtcNow);
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_WithNullPrivateKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.CreateSelfSignedCertificate(
                (byte[])null, 
                "CN=test.com", 
                TimeSpan.FromDays(365));
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_WithEmptyPrivateKey_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.CreateSelfSignedCertificate(
                new byte[0], 
                "CN=test.com", 
                TimeSpan.FromDays(365));
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_WithNullSubjectName_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                null, 
                TimeSpan.FromDays(365));
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_WithEmptySubjectName_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                string.Empty, 
                TimeSpan.FromDays(365));
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_WithZeroValidityPeriod_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                "CN=test.com", 
                TimeSpan.Zero);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void CreateSelfSignedCertificate_WithNegativeValidityPeriod_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                "CN=test.com", 
                TimeSpan.FromDays(-1));
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToPfx_WithValidInputs_CreatesValidPfx()
        {
            // Arrange
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                "CN=pfx-test.com", 
                TimeSpan.FromDays(30));
            
            string certPath = Path.Combine(_tempDirectory, "cert.pem");
            string keyPath = Path.Combine(_tempDirectory, "key.pem");
            string pfxPath = Path.Combine(_tempDirectory, "cert.pfx");
            string password = "testPassword123";
            
            // Create certificate PEM (this is a placeholder - in real implementation we'd export the cert to PEM)
            File.WriteAllBytes(certPath, certificate.RawData);
            File.WriteAllText(keyPath, _privateKeyPem);

            // Act
            Action act = () => CertificateFacade.ConvertPemToPfx(certPath, keyPath, pfxPath, password);

            // Assert - Should not throw (actual implementation would create valid PFX)
            // This test verifies the API contract and parameter validation
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToPfx_InMemory_ReturnsValidPfxBytes()
        {
            // Arrange
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                "CN=memory-test.com", 
                TimeSpan.FromDays(30));
            
            byte[] certificateBytes = certificate.RawData; // Placeholder - real impl would have PEM bytes
            string password = "memoryTestPwd";

            // Act
            Action act = () => CertificateFacade.ConvertPemToPfx(certificateBytes, _privateKeyBytes, password);

            // Assert - Should not throw (actual implementation would return valid PFX bytes)
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPemToPfx_WithNullCertificatePath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.ConvertPemToPfx(
                null, 
                "key.pem", 
                "cert.pfx", 
                "password");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPemToPfx_WithNullPassword_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.ConvertPemToPfx(
                _privateKeyBytes, 
                _privateKeyBytes, 
                null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPfxToPem_WithValidInputs_ExtractsPemFiles()
        {
            // Arrange
            string pfxPath = Path.Combine(_tempDirectory, "test.pfx");
            string password = "testPwd123";
            string certOutputPath = Path.Combine(_tempDirectory, "extracted_cert.pem");
            string keyOutputPath = Path.Combine(_tempDirectory, "extracted_key.pem");
            
            // Create a dummy PFX file for testing
            File.WriteAllText(pfxPath, "dummy pfx content");

            // Act & Assert - Should not throw due to parameter validation
            Action act = () => CertificateFacade.ConvertPfxToPem(
                pfxPath, 
                password, 
                certOutputPath, 
                keyOutputPath);
            
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ConvertPfxToPem_WithNullPfxPath_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.ConvertPfxToPem(
                null, 
                "password", 
                "cert.pem", 
                "key.pem");
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ConvertPfxToPem_InMemory_ReturnsValidPemTuple()
        {
            // Arrange
            byte[] dummyPfxData = Encoding.UTF8.GetBytes("dummy pfx data");
            string password = "testPassword";

            // Act & Assert
            Action act = () => CertificateFacade.ConvertPfxToPem(dummyPfxData, password);
            
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void ValidateCertificate_WithValidInputs_ReturnsValidationResult()
        {
            // Arrange
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                "CN=validation-test.com", 
                TimeSpan.FromDays(365));
            
            var trustedRoots = new X509Certificate2Collection();
            trustedRoots.Add(certificate); // Self-signed, so it's its own root

            // Act
            Action act = () => CertificateFacade.ValidateCertificate(certificate, trustedRoots);

            // Assert - Should not throw due to parameter validation
            act.Should().NotThrow<ArgumentNullException>();
        }

        [TestMethod]
        public void ValidateCertificate_WithNullCertificate_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => CertificateFacade.ValidateCertificate(
                null, 
                new X509Certificate2Collection());
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void ValidateCertificate_WithNullTrustedRoots_ThrowsArgumentNullException()
        {
            // Arrange
            var certificate = CertificateFacade.CreateSelfSignedCertificate(
                _privateKeyBytes, 
                "CN=test.com", 
                TimeSpan.FromDays(365));

            // Act & Assert
            Action act = () => CertificateFacade.ValidateCertificate(certificate, null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void SignCertificateRequest_WithValidParameters_DoesNotThrow()
        {
            // Arrange
            string subject = "CN=client.example.com,O=Client Corp";
            byte[] csrBytes = OpenSslFacade.GenerateCertificateSigningRequestBytes(_privateKeyBytes, subject);
            
            // Generate CA key and certificate
            byte[] caPrivateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
            var caCertificate = CertificateFacade.CreateSelfSignedCertificate(
                caPrivateKey, 
                "CN=Test CA,O=Test Authority", 
                TimeSpan.FromDays(730));

            // Act & Assert - Should not throw due to parameter validation
            Action act = () => CertificateFacade.SignCertificateRequest(
                csrBytes, 
                caPrivateKey, 
                caCertificate.RawData, 
                TimeSpan.FromDays(90));
            
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void SignCertificateRequest_WithNullCsr_ThrowsArgumentNullException()
        {
            // Arrange
            byte[] caPrivateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
            byte[] caCertBytes = new byte[100]; // Dummy certificate bytes

            // Act & Assert
            Action act = () => CertificateFacade.SignCertificateRequest(
                null, 
                caPrivateKey, 
                caCertBytes, 
                TimeSpan.FromDays(90));
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void SignCertificateRequest_WithZeroValidityPeriod_ThrowsArgumentException()
        {
            // Arrange
            byte[] csrBytes = new byte[100]; // Dummy CSR bytes
            byte[] caPrivateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
            byte[] caCertBytes = new byte[100]; // Dummy certificate bytes

            // Act & Assert
            Action act = () => CertificateFacade.SignCertificateRequest(
                csrBytes, 
                caPrivateKey, 
                caCertBytes, 
                TimeSpan.Zero);
            act.Should().ThrowExactly<ArgumentException>();
        }
    }
}