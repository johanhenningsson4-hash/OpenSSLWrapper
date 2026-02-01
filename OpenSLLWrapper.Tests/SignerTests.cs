using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSLLWrapper;

namespace OpenSLLWrapper.Tests
{
    [TestClass]
    public class SignerTests
    {
        [TestMethod]
        public void SignVerify_Pkcs1_Roundtrip()
        {
            // Arrange
            byte[] privPem = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(2048);
            byte[] pubPem = OpenSLLWrapper.ExportPublicKeyPemFromPrivateKeyBytes(privPem);
            byte[] data = Encoding.UTF8.GetBytes("unit-test-challenge");

            // Act
            string sigB64 = OpenSLLWrapper.SignChallengeData(data, privPem, usePss: false);
            byte[] sig = Convert.FromBase64String(sigB64);
            bool ok = OpenSLLWrapper.VerifyChallengeData(data, sig, pubPem, usePss: false);

            // Assert
            Assert.IsTrue(ok, "PKCS#1 signature did not verify");
        }

        [TestMethod]
        public void SignVerify_Pss_Roundtrip()
        {
            // Arrange
            byte[] privPem = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(2048);
            byte[] pubPem = OpenSLLWrapper.ExportPublicKeyPemFromPrivateKeyBytes(privPem);
            byte[] data = Encoding.UTF8.GetBytes("unit-test-challenge-pss");

            // Act
            string sigB64 = OpenSLLWrapper.SignChallengeData(data, privPem, usePss: true);
            byte[] sig = Convert.FromBase64String(sigB64);
            bool ok = OpenSLLWrapper.VerifyChallengeData(data, sig, pubPem, usePss: true);

            // Assert
            Assert.IsTrue(ok, "PSS signature did not verify");
        }

        [TestMethod]
        public void Pkcs1_Pkcs8_Conversion_Roundtrip()
        {
            // Arrange
            byte[] pkcs1 = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(2048);

            // Act
            byte[] pkcs8 = OpenSLLWrapper.ConvertPkcs1ToPkcs8PemBytes(pkcs1);
            Assert.IsNotNull(pkcs8);
            Assert.IsTrue(pkcs8.Length > 0);

            byte[] pkcs1Back = OpenSLLWrapper.ConvertPkcs8ToPkcs1PemBytes(pkcs8);
            Assert.IsNotNull(pkcs1Back);
            Assert.IsTrue(pkcs1Back.Length > 0);

            string pkcs1Text = Encoding.ASCII.GetString(pkcs1Back);
            Assert.IsTrue(pkcs1Text.Contains("RSA PRIVATE KEY"), "Roundtrip did not produce PKCS#1 PEM header");
        }
    }
}
