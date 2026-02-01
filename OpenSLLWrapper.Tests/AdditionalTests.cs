using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSLLWrapper;

namespace OpenSLLWrapper.Tests
{
    [TestClass]
    public class AdditionalTests
    {
        [TestMethod]
        public void GenerateRsaPrivateKey_FileAndStream_Roundtrip()
        {
            // Stream overload
            using (var ms = new MemoryStream())
            {
                OpenSLLWrapper.GenerateRsaPrivateKey(ms, 1024);
                var arr = ms.ToArray();
                Assert.IsNotNull(arr);
                Assert.IsTrue(arr.Length > 0);
                var txt = Encoding.ASCII.GetString(arr);
                Assert.IsTrue(txt.Contains("PRIVATE KEY"));
            }

            // File overload
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pem");
            try
            {
                OpenSLLWrapper.GenerateRsaPrivateKey(path, 1024);
                Assert.IsTrue(File.Exists(path));
                string text = File.ReadAllText(path);
                Assert.IsTrue(text.Contains("PRIVATE KEY"));
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }

        [TestMethod]
        public void GenerateCertificateSigningRequest_Stream_Roundtrip()
        {
            byte[] priv = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(1024);
            byte[] csr = OpenSLLWrapper.GenerateCertificateSigningRequestBytes(priv, "CN=unit-test");
            Assert.IsNotNull(csr);
            string txt = Encoding.ASCII.GetString(csr);
            Assert.IsTrue(txt.Contains("CERTIFICATE REQUEST") || txt.Contains("CERTIFICATE REQUEST"));
        }

        [TestMethod]
        public void SignVerify_Base64_Wrapper_Roundtrip()
        {
            byte[] priv = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(1024);
            string privPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pem");
            string pubPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pub.pem");

            try
            {
                File.WriteAllBytes(privPath, priv);
                byte[] pub = OpenSLLWrapper.ExportPublicKeyPemFromPrivateKeyBytes(priv);
                File.WriteAllBytes(pubPath, pub);

                string challenge = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello-world-base64"));
                string sigB64 = OpenSLLWrapper.SignBase64Challenge(challenge, privPath);
                Assert.IsFalse(string.IsNullOrWhiteSpace(sigB64));

                bool ok = OpenSLLWrapper.VerifyBase64Signature(challenge, sigB64, pubPath, usePss: false);
                Assert.IsTrue(ok);
            }
            finally
            {
                if (File.Exists(privPath)) File.Delete(privPath);
                if (File.Exists(pubPath)) File.Delete(pubPath);
            }
        }

        [TestMethod]
        public void SaveLoadPemFileEncrypted_Roundtrip()
        {
            byte[] pem = Encoding.UTF8.GetBytes("---DUMMY PEM---\nvalue\n");
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".enc");
            try
            {
                OpenSLLWrapper.SavePemFileEncrypted(path, pem, "test-password", iterations: 1000);
                Assert.IsTrue(File.Exists(path));
                byte[] loaded = OpenSLLWrapper.LoadPemFileEncrypted(path, "test-password", iterations: 1000);
                CollectionAssert.AreEqual(pem, loaded);
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }

        [TestMethod]
        public void SavePemFileSecure_NoCrash_And_WritesFile()
        {
            byte[] pem = Encoding.UTF8.GetBytes("---DUMMY PEM SECURE---\n");
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pem");
            try
            {
                // Should not throw on any platform; on non-Windows ACL modification is ignored
                OpenSLLWrapper.SavePemFileSecure(path, pem);
                Assert.IsTrue(File.Exists(path));
                byte[] got = File.ReadAllBytes(path);
                CollectionAssert.AreEqual(pem, got);
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }

        [TestMethod]
        public void ExportEncryptedPkcs8Pem_Import_Roundtrip()
        {
            byte[] priv = OpenSLLWrapper.GenerateRsaPrivateKeyBytes(1024);
            string privPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pem");
            string pkcs8Path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".pk8");
            string outPkcs1 = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".out.pem");

            try
            {
                File.WriteAllBytes(privPath, priv);
                OpenSLLWrapper.ExportEncryptedPkcs8Pem(privPath, pkcs8Path, "pw");
                Assert.IsTrue(File.Exists(pkcs8Path));

                OpenSLLWrapper.ImportEncryptedPkcs8ToPkcs1Pem(pkcs8Path, "pw", outPkcs1);
                Assert.IsTrue(File.Exists(outPkcs1));
                string outText = File.ReadAllText(outPkcs1);
                Assert.IsTrue(outText.Contains("RSA PRIVATE KEY"));
            }
            finally
            {
                if (File.Exists(privPath)) File.Delete(privPath);
                if (File.Exists(pkcs8Path)) File.Delete(pkcs8Path);
                if (File.Exists(outPkcs1)) File.Delete(outPkcs1);
            }
        }
    }
}
