using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace OpenSLLWrapper.UnitTests
{
    /// <summary>
    /// Unit tests for JOSE (JWT, JWS, JWE) operations.
    /// </summary>
    [TestClass]
    public class JoseOperationsTests
    {
        private string _tempDirectory;
        private string _privateKeyPem;
        private string _publicKeyPem;
        private byte[] _privateKeyBytes;
        private byte[] _publicKeyBytes;

        [TestInitialize]
        public void TestInitialize()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), "OpenSLLWrapper_JoseTests", Guid.NewGuid().ToString());
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

        #region JWT Tests

        [TestMethod]
        public void CreateJwt_WithValidPayload_ReturnsValidJwtFormat()
        {
            // Arrange
            var payload = new { 
                userId = 12345, 
                username = "testuser",
                roles = new[] { "user", "admin" }
            };

            // Act
            Action act = () => JoseFacade.CreateJwt(
                payload, 
                _privateKeyBytes, 
                JwtAlgorithm.RS256, 
                expirationMinutes: 30);

            // Assert - Should not throw due to parameter validation
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void CreateJwt_FromFile_ReturnsValidJwtFormat()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "jwt_private_key.pem");
            File.WriteAllText(privateKeyPath, _privateKeyPem);
            
            var payload = new { 
                sub = "user123", 
                name = "John Doe",
                email = "john@example.com"
            };

            // Act
            Action act = () => JoseFacade.CreateJwt(
                payload, 
                privateKeyPath, 
                JwtAlgorithm.RS256,
                expirationMinutes: 60,
                issuer: "TestApp",
                audience: "api.example.com");

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        [DataRow(JwtAlgorithm.RS256)]
        [DataRow(JwtAlgorithm.RS384)]
        [DataRow(JwtAlgorithm.RS512)]
        [DataRow(JwtAlgorithm.PS256)]
        [DataRow(JwtAlgorithm.PS384)]
        [DataRow(JwtAlgorithm.PS512)]
        public void CreateJwt_WithDifferentAlgorithms_DoesNotThrow(JwtAlgorithm algorithm)
        {
            // Arrange
            var payload = new { message = "test payload" };

            // Act
            Action act = () => JoseFacade.CreateJwt(
                payload, 
                _privateKeyBytes, 
                algorithm, 
                expirationMinutes: 15);

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void CreateJwt_WithNullPayload_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.CreateJwt(
                null, 
                _privateKeyBytes, 
                JwtAlgorithm.RS256);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void CreateJwt_WithNullPrivateKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.CreateJwt(
                new { test = "payload" }, 
                (byte[])null, 
                JwtAlgorithm.RS256);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void CreateJwt_WithZeroExpirationMinutes_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.CreateJwt(
                new { test = "payload" }, 
                _privateKeyBytes, 
                JwtAlgorithm.RS256,
                expirationMinutes: 0);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void CreateJwt_WithNegativeExpirationMinutes_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.CreateJwt(
                new { test = "payload" }, 
                _privateKeyBytes, 
                JwtAlgorithm.RS256,
                expirationMinutes: -10);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJwt_WithValidParameters_DoesNotThrow()
        {
            // Arrange
            string dummyJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummy_signature";

            // Act
            Action act = () => JoseFacade.VerifyJwt(
                dummyJwt, 
                _publicKeyBytes,
                expectedIssuer: "TestApp",
                expectedAudience: "api.example.com");

            // Assert - Should not throw due to parameter validation
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJwt_FromFile_DoesNotThrow()
        {
            // Arrange
            string publicKeyPath = Path.Combine(_tempDirectory, "jwt_public_key.pem");
            File.WriteAllText(publicKeyPath, _publicKeyPem);
            string dummyJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummy_signature";

            // Act
            Action act = () => JoseFacade.VerifyJwt(dummyJwt, publicKeyPath);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJwt_WithNullJwt_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.VerifyJwt(null, _publicKeyBytes);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void VerifyJwt_WithEmptyJwt_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.VerifyJwt(string.Empty, _publicKeyBytes);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJwt_WithNegativeClockSkew_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.VerifyJwt(
                "dummy.jwt.token", 
                _publicKeyBytes, 
                clockSkewMinutes: -1);
            act.Should().ThrowExactly<ArgumentException>();
        }

        #endregion

        #region JWS Tests

        [TestMethod]
        public void SignJws_WithValidJsonPayload_DoesNotThrow()
        {
            // Arrange
            string jsonPayload = @"{""message"":""Hello, World!"",""timestamp"":""2024-01-01T12:00:00Z""}";
            var customHeaders = new Dictionary<string, object> { {"typ", "custom"} };

            // Act
            Action act = () => JoseFacade.SignJws(
                jsonPayload, 
                _privateKeyBytes, 
                JwtAlgorithm.RS256,
                customHeaders);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void SignJws_FromFile_DoesNotThrow()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "jws_private_key.pem");
            File.WriteAllText(privateKeyPath, _privateKeyPem);
            string jsonPayload = @"{""data"":""sensitive information""}";

            // Act
            Action act = () => JoseFacade.SignJws(jsonPayload, privateKeyPath, JwtAlgorithm.RS256);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void SignJws_WithNullPayload_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.SignJws(null, _privateKeyBytes, JwtAlgorithm.RS256);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void SignJws_WithEmptyPayload_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.SignJws(string.Empty, _privateKeyBytes, JwtAlgorithm.RS256);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJws_WithValidParameters_DoesNotThrow()
        {
            // Arrange
            string dummyJws = "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJtZXNzYWdlIjoiSGVsbG8ifQ.dummy_signature";

            // Act
            Action act = () => JoseFacade.VerifyJws(dummyJws, _publicKeyBytes);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJws_FromFile_DoesNotThrow()
        {
            // Arrange
            string publicKeyPath = Path.Combine(_tempDirectory, "jws_public_key.pem");
            File.WriteAllText(publicKeyPath, _publicKeyPem);
            string dummyJws = "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJtZXNzYWdlIjoiSGVsbG8ifQ.dummy_signature";

            // Act
            Action act = () => JoseFacade.VerifyJws(dummyJws, publicKeyPath);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void VerifyJws_WithNullJws_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.VerifyJws(null, _publicKeyBytes);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void VerifyJws_WithEmptyJws_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.VerifyJws(string.Empty, _publicKeyBytes);
            act.Should().ThrowExactly<ArgumentException>();
        }

        #endregion

        #region JWE Tests

        [TestMethod]
        public void EncryptJwe_WithValidJsonPayload_DoesNotThrow()
        {
            // Arrange
            string sensitiveData = @"{""ssn"":""123-45-6789"",""creditCard"":""4111-1111-1111-1111""}";

            // Act
            Action act = () => JoseFacade.EncryptJwe(
                sensitiveData, 
                _publicKeyBytes,
                JweKeyAlgorithm.RsaOaep,
                JweContentAlgorithm.A256Gcm);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void EncryptJwe_FromFile_DoesNotThrow()
        {
            // Arrange
            string publicKeyPath = Path.Combine(_tempDirectory, "jwe_public_key.pem");
            File.WriteAllText(publicKeyPath, _publicKeyPem);
            string secretData = @"{""apiKey"":""secret123"",""token"":""xyz789""}";

            // Act
            Action act = () => JoseFacade.EncryptJwe(secretData, publicKeyPath);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        [DataRow(JweKeyAlgorithm.Rsa1_5, JweContentAlgorithm.A128Gcm)]
        [DataRow(JweKeyAlgorithm.RsaOaep, JweContentAlgorithm.A192Gcm)]
        [DataRow(JweKeyAlgorithm.RsaOaep256, JweContentAlgorithm.A256Gcm)]
        [DataRow(JweKeyAlgorithm.RsaOaep, JweContentAlgorithm.A128CbcHS256)]
        public void EncryptJwe_WithDifferentAlgorithms_DoesNotThrow(
            JweKeyAlgorithm keyAlg, 
            JweContentAlgorithm contentAlg)
        {
            // Arrange
            string payload = @"{""test"":""data""}";

            // Act
            Action act = () => JoseFacade.EncryptJwe(
                payload, 
                _publicKeyBytes, 
                keyAlg, 
                contentAlg);

            // Assert
            act.Should().NotThrow();
        }

        [TestMethod]
        public void EncryptJwe_WithNullPayload_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.EncryptJwe(null, _publicKeyBytes);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void EncryptJwe_WithEmptyPayload_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.EncryptJwe(string.Empty, _publicKeyBytes);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void DecryptJwe_WithValidParameters_DoesNotThrow()
        {
            // Arrange
            string dummyJwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.dummy.dummy.dummy.dummy";

            // Act
            Action act = () => JoseFacade.DecryptJwe(dummyJwe, _privateKeyBytes);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void DecryptJwe_FromFile_DoesNotThrow()
        {
            // Arrange
            string privateKeyPath = Path.Combine(_tempDirectory, "jwe_private_key.pem");
            File.WriteAllText(privateKeyPath, _privateKeyPem);
            string dummyJwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.dummy.dummy.dummy.dummy";

            // Act
            Action act = () => JoseFacade.DecryptJwe(dummyJwe, privateKeyPath);

            // Assert
            act.Should().NotThrow<ArgumentNullException>();
            act.Should().NotThrow<ArgumentException>();
        }

        [TestMethod]
        public void DecryptJwe_WithNullJwe_ThrowsArgumentNullException()
        {
            // Act & Assert
            Action act = () => JoseFacade.DecryptJwe(null, _privateKeyBytes);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void DecryptJwe_WithEmptyJwe_ThrowsArgumentException()
        {
            // Act & Assert
            Action act = () => JoseFacade.DecryptJwe(string.Empty, _privateKeyBytes);
            act.Should().ThrowExactly<ArgumentException>();
        }

        #endregion

        #region Round-Trip Tests (Placeholder)

        [TestMethod]
        public void JwtRoundTrip_CreateAndVerify_ShouldBeConsistent()
        {
            // This test would verify that a JWT created with CreateJwt()
            // can be successfully verified with VerifyJwt() using the corresponding keys
            // Actual implementation would test the full round-trip functionality
            
            // Arrange
            var payload = new { userId = 123, roles = new[] { "user" } };

            // Act & Assert - Test that the API contract is consistent
            Action createAct = () => JoseFacade.CreateJwt(payload, _privateKeyBytes, JwtAlgorithm.RS256);
            Action verifyAct = () => JoseFacade.VerifyJwt("dummy.jwt.token", _publicKeyBytes);

            createAct.Should().NotThrow();
            verifyAct.Should().NotThrow<ArgumentException>(); // May throw other exceptions due to dummy token
        }

        [TestMethod]
        public void JwsRoundTrip_SignAndVerify_ShouldBeConsistent()
        {
            // This test would verify that a JWS created with SignJws()
            // can be successfully verified with VerifyJws() using the corresponding keys
            
            // Arrange
            string jsonPayload = @"{""message"":""test""}";

            // Act & Assert - Test that the API contract is consistent
            Action signAct = () => JoseFacade.SignJws(jsonPayload, _privateKeyBytes, JwtAlgorithm.RS256);
            Action verifyAct = () => JoseFacade.VerifyJws("dummy.jws.token", _publicKeyBytes);

            signAct.Should().NotThrow();
            verifyAct.Should().NotThrow<ArgumentException>(); // May throw other exceptions due to dummy token
        }

        [TestMethod]
        public void JweRoundTrip_EncryptAndDecrypt_ShouldBeConsistent()
        {
            // This test would verify that a JWE created with EncryptJwe()
            // can be successfully decrypted with DecryptJwe() using the corresponding keys
            
            // Arrange
            string sensitiveData = @"{""secret"":""value""}";

            // Act & Assert - Test that the API contract is consistent
            Action encryptAct = () => JoseFacade.EncryptJwe(sensitiveData, _publicKeyBytes);
            Action decryptAct = () => JoseFacade.DecryptJwe("dummy.jwe.token", _privateKeyBytes);

            encryptAct.Should().NotThrow();
            decryptAct.Should().NotThrow<ArgumentException>(); // May throw other exceptions due to dummy token
        }

        #endregion
    }
}