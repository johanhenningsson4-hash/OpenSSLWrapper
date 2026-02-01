using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Facade exposing the public, intended API for key management, CSR creation and signing.
    /// Use this class as the single public surface for consuming the library.
    /// </summary>
    public static class OpenSslFacade
    {
        /// <summary>
        /// Generate an RSA private key and write it as a PEM file (PKCS#1 RSA PRIVATE KEY).
        /// </summary>
        /// <param name="outputPath">File path to write the PEM private key.</param>
        /// <param name="keySize">Key size in bits (e.g. 2048, 4096).</param>
        public static void GenerateRsaPrivateKey(string outputPath, int keySize = 4096)
        {
            OpenSLLWrapper.GenerateRsaPrivateKey(outputPath, keySize);
        }

        /// <summary>
        /// Asynchronously generate an RSA private key and write it as a PEM file.
        /// </summary>
        public static Task GenerateRsaPrivateKeyAsync(string outputPath, int keySize = 4096, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.GenerateRsaPrivateKeyAsync(outputPath, keySize, cancellationToken);
        }

        /// <summary>
        /// Generate an RSA private key and write PEM bytes to the provided stream.
        /// </summary>
        public static void GenerateRsaPrivateKey(Stream outputStream, int keySize = 4096)
        {
            OpenSLLWrapper.GenerateRsaPrivateKey(outputStream, keySize);
        }

        /// <summary>
        /// Generate an RSA private key and return the PEM bytes.
        /// </summary>
        public static byte[] GenerateRsaPrivateKeyBytes(int keySize = 4096)
        {
            return OpenSLLWrapper.GenerateRsaPrivateKeyBytes(keySize);
        }

        /// <summary>
        /// Create a CSR (PEM) using the provided private key PEM file and subject.
        /// </summary>
        public static void GenerateCertificateSigningRequest(string keyPath, string outputPath, string subject)
        {
            OpenSLLWrapper.GenerateCertificateSigningRequest(keyPath, outputPath, subject);
        }

        /// <summary>
        /// Asynchronously create a CSR (PEM) using the provided private key PEM file and subject.
        /// </summary>
        public static Task GenerateCertificateSigningRequestAsync(string keyPath, string outputPath, string subject, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.GenerateCertificateSigningRequestAsync(keyPath, outputPath, subject, cancellationToken);
        }

        /// <summary>
        /// Create a CSR (PEM) from private key bytes and subject and return PEM bytes.
        /// </summary>
        public static byte[] GenerateCertificateSigningRequestBytes(byte[] privateKeyPem, string subject)
        {
            return OpenSLLWrapper.GenerateCertificateSigningRequestBytes(privateKeyPem, subject);
        }

        /// <summary>
        /// Sign a base64-encoded challenge using an RSA private key PEM file and return base64 signature.
        /// </summary>
        public static string SignBase64Challenge(string base64Challenge, string keyPath)
        {
            return OpenSLLWrapper.SignBase64Challenge(base64Challenge, keyPath);
        }

        /// <summary>
        /// Asynchronously sign a base64-encoded challenge using an RSA private key PEM file and return base64 signature.
        /// </summary>
        public static Task<string> SignBase64ChallengeAsync(string base64Challenge, string keyPath, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.SignBase64ChallengeAsync(base64Challenge, keyPath, cancellationToken);
        }

        /// <summary>
        /// Sign raw data (byte array) using a private key PEM bytes and return base64 signature.
        /// </summary>
        public static string SignChallengeData(byte[] data, byte[] privateKeyPem)
        {
            return OpenSLLWrapper.SignChallengeData(data, privateKeyPem);
        }

        /// <summary>
        /// Convert a PKCS#1 PEM file to an unencrypted PKCS#8 PEM file.
        /// </summary>
        public static void ConvertPkcs1ToPkcs8Pem(string pkcs1Path, string pkcs8Path)
        {
            OpenSLLWrapper.ConvertPkcs1ToPkcs8Pem(pkcs1Path, pkcs8Path);
        }

        /// <summary>
        /// Convert PKCS#1 PEM bytes to PKCS#8 PEM bytes.
        /// </summary>
        public static byte[] ConvertPkcs1ToPkcs8PemBytes(byte[] pkcs1Pem)
        {
            return OpenSLLWrapper.ConvertPkcs1ToPkcs8PemBytes(pkcs1Pem);
        }

        /// <summary>
        /// Convert an unencrypted PKCS#8 PEM file to a PKCS#1 PEM file.
        /// </summary>
        public static void ConvertPkcs8ToPkcs1Pem(string pkcs8Path, string pkcs1Path)
        {
            OpenSLLWrapper.ConvertPkcs8ToPkcs1Pem(pkcs8Path, pkcs1Path);
        }

        /// <summary>
        /// Convert PKCS#8 PEM bytes to PKCS#1 PEM bytes.
        /// </summary>
        public static byte[] ConvertPkcs8ToPkcs1PemBytes(byte[] pkcs8Pem)
        {
            return OpenSLLWrapper.ConvertPkcs8ToPkcs1PemBytes(pkcs8Pem);
        }

        /// <summary>
        /// Export a public key PEM derived from a private key PEM file.
        /// </summary>
        public static void ExportPublicKeyPemFromPrivateKey(string keyPath, string outputPath)
        {
            OpenSLLWrapper.ExportPublicKeyPemFromPrivateKey(keyPath, outputPath);
        }

        /// <summary>
        /// Export a public key PEM derived from private key PEM bytes.
        /// </summary>
        public static byte[] ExportPublicKeyPemFromPrivateKeyBytes(byte[] privateKeyPem)
        {
            return OpenSLLWrapper.ExportPublicKeyPemFromPrivateKeyBytes(privateKeyPem);
        }

        /// <summary>
        /// Export an encrypted PKCS#8 PEM (password protected) from an input private key PEM file.
        /// </summary>
        public static void ExportEncryptedPkcs8Pem(string inputPrivateKeyPath, string outputPkcs8Path, string password)
        {
            OpenSLLWrapper.ExportEncryptedPkcs8Pem(inputPrivateKeyPath, outputPkcs8Path, password);
        }

        /// <summary>
        /// Import an encrypted PKCS#8 PEM (password protected) and write an unencrypted PKCS#1 PEM file.
        /// </summary>
        public static void ImportEncryptedPkcs8ToPkcs1Pem(string encryptedPkcs8Path, string password, string outputPkcs1Path)
        {
            OpenSLLWrapper.ImportEncryptedPkcs8ToPkcs1Pem(encryptedPkcs8Path, password, outputPkcs1Path);
        }

        /// <summary>
        /// Asynchronously export an encrypted PKCS#8 PEM file from an input private key PEM file.
        /// </summary>
        public static Task ExportEncryptedPkcs8PemAsync(string inputPrivateKeyPath, string outputPkcs8Path, string password, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.ExportEncryptedPkcs8PemAsync(inputPrivateKeyPath, outputPkcs8Path, password, cancellationToken);
        }

        /// <summary>
        /// Asynchronously import an encrypted PKCS#8 PEM into an unencrypted PKCS#1 PEM file.
        /// </summary>
        public static Task ImportEncryptedPkcs8ToPkcs1PemAsync(string encryptedPkcs8Path, string password, string outputPkcs1Path, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.ImportEncryptedPkcs8ToPkcs1PemAsync(encryptedPkcs8Path, password, outputPkcs1Path, cancellationToken);
        }
    }
}
