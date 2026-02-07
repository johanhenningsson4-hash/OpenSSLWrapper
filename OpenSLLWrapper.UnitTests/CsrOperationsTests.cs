using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for Certificate Signing Request (CSR) operations.
    /// </summary>
    [TestClass]
    public class CsrOperationsTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_UnitTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            
            // Generate a test private key
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
        public void GenerateCertificateSigningRequest_ValidInput_CreatesValidCsr()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "private_key.pem");
            string csrPath = Path.Combine(_tempDirectory, "test.csr");
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";
            
            File.WriteAllText(privateKeyPath, _privateKeyPem);

            // Act
            OpenSslFacade.GenerateCertificateSigningRequest(privateKeyPath, csrPath, subject);

            // Assert
            File.Exists(csrPath).Should().BeTrue();
            
            string csrContent = File.ReadAllText(csrPath);
            csrContent.Should().StartWith("-----BEGIN CERTIFICATE REQUEST-----");
            csrContent.Should().EndWith("-----END CERTIFICATE REQUEST-----");
        }

        [TestMethod]
        public void GenerateCertificateSigningRequestBytes_ValidInput_ReturnsValidCsr()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";

            // Act
            byte[] csrBytes = OpenSslFacade.GenerateCertificateSigningRequestBytes(privateKeyBytes, subject);

            // Assert
            csrBytes.Should().NotBeNull();
            csrBytes.Should().NotBeEmpty();
            
            string csrContent = Encoding.UTF8.GetString(csrBytes);
            csrContent.Should().StartWith("-----BEGIN CERTIFICATE REQUEST-----");
            csrContent.Should().EndWith("-----END CERTIFICATE REQUEST-----");
        }

        [TestMethod]
        public void GenerateCertificateSigningRequest_ToStream_WritesValidCsr()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";

            // Act
            using var privateKeyStream = new MemoryStream(privateKeyBytes);
            using var csrStream = new MemoryStream();
            
            OpenSslFacade.GenerateCertificateSigningRequest(privateKeyStream, csrStream, subject);

            // Assert
            csrStream.Length.Should().BeGreaterThan(0);
            
            string csrContent = Encoding.UTF8.GetString(csrStream.ToArray());
            csrContent.Should().StartWith("-----BEGIN CERTIFICATE REQUEST-----");
            csrContent.Should().EndWith("-----END CERTIFICATE REQUEST-----");
        }

        [TestMethod]
        [DataRow("/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com")]
        [DataRow("/CN=test.example.com")]
        [DataRow("/C=GB/O=Example Corp/CN=api.example.com")]
        [DataRow("/C=DE/ST=Bavaria/L=Munich/O=Test GmbH/OU=IT/CN=secure.test.de")]
        public void GenerateCertificateSigningRequestBytes_VariousSubjects_CreatesValidCsrs(string subject)
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act
            byte[] csrBytes = OpenSslFacade.GenerateCertificateSigningRequestBytes(privateKeyBytes, subject);

            // Assert
            csrBytes.Should().NotBeNull();
            csrBytes.Should().NotBeEmpty();
            
            string csrContent = Encoding.UTF8.GetString(csrBytes);
            csrContent.Should().StartWith("-----BEGIN CERTIFICATE REQUEST-----");
            csrContent.Should().EndWith("-----END CERTIFICATE REQUEST-----");
        }

        [TestMethod]
        public void GenerateCertificateSigningRequestBytes_NullPrivateKey_ThrowsArgumentNullException()
        {
            // Arrange
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";

            // Act & Assert
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequestBytes(null, subject);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void GenerateCertificateSigningRequestBytes_EmptyPrivateKey_ThrowsArgumentException()
        {
            // Arrange
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";

            // Act & Assert
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequestBytes(new byte[0], subject);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void GenerateCertificateSigningRequestBytes_NullSubject_ThrowsArgumentNullException()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act & Assert
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequestBytes(privateKeyBytes, null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void GenerateCertificateSigningRequestBytes_EmptySubject_ThrowsArgumentException()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);

            // Act & Assert
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequestBytes(privateKeyBytes, string.Empty);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void GenerateCertificateSigningRequest_NullPrivateKeyPath_ThrowsArgumentNullException()
        {
            // Arrange
            string csrPath = Path.Combine(_tempDirectory, "test.csr");
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";

            // Act & Assert
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequest(null, csrPath, subject);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void GenerateCertificateSigningRequest_NonExistentPrivateKey_ThrowsFileNotFoundException()
        {
            // Arrange
            string nonExistentKeyPath = Path.Combine(_tempDirectory, "nonexistent.pem");
            string csrPath = Path.Combine(_tempDirectory, "test.csr");
            string subject = "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com";

            // Act & Assert
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequest(nonExistentKeyPath, csrPath, subject);
            act.Should().Throw<FileNotFoundException>();
        }

        [TestMethod]
        public void GenerateCertificateSigningRequest_InvalidSubjectFormat_ShouldHandleGracefully()
        {
            // Arrange
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(_privateKeyPem);
            string invalidSubject = "InvalidSubjectFormat";

            // Act & Assert - Should either work or throw a meaningful exception
            Action act = () => OpenSslFacade.GenerateCertificateSigningRequestBytes(privateKeyBytes, invalidSubject);
            
            // This test documents current behavior - the method should either:
            // 1. Handle the invalid format gracefully, or 
            // 2. Throw a clear, meaningful exception
            act.Should().NotThrow<NullReferenceException>();
        }
    }
}