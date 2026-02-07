using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Facade exposing the public, intended API for key management, CSR creation and signing.
    /// Use this class as the single public surface for consuming the library.
    /// This facade provides a simplified interface over the underlying OpenSLLWrapper implementation.
    /// </summary>
    /// <remarks>
    /// All operations support both file-based and byte-array-based workflows to provide flexibility
    /// for applications that need to avoid filesystem I/O or work with in-memory data.
    /// The library uses BouncyCastle for cryptographic operations and defaults to PKCS#1 v1.5 
    /// signatures for compatibility with standard OpenSSL tools.
    /// </remarks>
    public static class OpenSslFacade
    {
        /// <summary>
        /// Generate an RSA private key and write it as a PEM file (PKCS#1 RSA PRIVATE KEY).
        /// </summary>
        /// <param name="outputPath">File path to write the PEM private key. Must not be null or empty.</param>
        /// <param name="keySize">Key size in bits. Common values are 2048, 3072, and 4096. Default is 4096.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="outputPath"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="outputPath"/> is empty or <paramref name="keySize"/> is invalid.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the directory for <paramref name="outputPath"/> does not exist.</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the application lacks permission to write to the specified path.</exception>
        /// <example>
        /// <code>
        /// // Generate a 2048-bit RSA key
        /// OpenSslFacade.GenerateRsaPrivateKey("private_key.pem", 2048);
        /// </code>
        /// </example>
        public static void GenerateRsaPrivateKey(string outputPath, int keySize = 4096)
        {
            OpenSLLWrapper.GenerateRsaPrivateKey(outputPath, keySize);
        }

        /// <summary>
        /// Asynchronously generate an RSA private key and write it as a PEM file.
        /// This method provides the same functionality as <see cref="GenerateRsaPrivateKey(string, int)"/>
        /// but with asynchronous execution and cancellation support.
        /// </summary>
        /// <param name="outputPath">File path to write the PEM private key. Must not be null or empty.</param>
        /// <param name="keySize">Key size in bits. Common values are 2048, 3072, and 4096. Default is 4096.</param>
        /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="outputPath"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="outputPath"/> is empty or <paramref name="keySize"/> is invalid.</exception>
        /// <exception cref="OperationCanceledException">Thrown when the operation is canceled via <paramref name="cancellationToken"/>.</exception>
        /// <example>
        /// <code>
        /// // Generate key asynchronously with cancellation support
        /// using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        /// await OpenSslFacade.GenerateRsaPrivateKeyAsync("private_key.pem", 2048, cts.Token);
        /// </code>
        /// </example>
        public static Task GenerateRsaPrivateKeyAsync(string outputPath, int keySize = 4096, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.GenerateRsaPrivateKeyAsync(outputPath, keySize, cancellationToken);
        }

        /// <summary>
        /// Generate an RSA private key and write PEM bytes to the provided stream.
        /// This method allows for in-memory key generation without requiring filesystem access.
        /// </summary>
        /// <param name="outputStream">The stream to write the PEM private key bytes to. Must not be null and must be writable.</param>
        /// <param name="keySize">Key size in bits. Common values are 2048, 3072, and 4096. Default is 4096.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="outputStream"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="outputStream"/> is not writable or <paramref name="keySize"/> is invalid.</exception>
        /// <exception cref="NotSupportedException">Thrown when the stream does not support writing.</exception>
        /// <example>
        /// <code>
        /// using var stream = new MemoryStream();
        /// OpenSslFacade.GenerateRsaPrivateKey(stream, 2048);
        /// byte[] keyBytes = stream.ToArray();
        /// </code>
        /// </example>
        public static void GenerateRsaPrivateKey(Stream outputStream, int keySize = 4096)
        {
            OpenSLLWrapper.GenerateRsaPrivateKey(outputStream, keySize);
        }

        /// <summary>
        /// Generate an RSA private key and return the PEM bytes.
        /// This method provides fully in-memory key generation without any I/O operations.
        /// </summary>
        /// <param name="keySize">Key size in bits. Common values are 2048, 3072, and 4096. Default is 4096.</param>
        /// <returns>A byte array containing the RSA private key in PKCS#1 PEM format.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="keySize"/> is invalid (typically less than 1024 or not a power of 2).</exception>
        /// <example>
        /// <code>
        /// // Generate key in memory
        /// byte[] keyBytes = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// string keyPem = Encoding.UTF8.GetString(keyBytes);
        /// </code>
        /// </example>
        public static byte[] GenerateRsaPrivateKeyBytes(int keySize = 4096)
        {
            return OpenSLLWrapper.GenerateRsaPrivateKeyBytes(keySize);
        }

        /// <summary>
        /// Create a Certificate Signing Request (CSR) in PEM format using the provided private key PEM file and subject.
        /// The CSR can be submitted to a Certificate Authority (CA) to obtain a signed certificate.
        /// </summary>
        /// <param name="keyPath">Path to the private key PEM file. Must not be null or empty.</param>
        /// <param name="outputPath">Path where the CSR PEM file will be written. Must not be null or empty.</param>
        /// <param name="subject">The subject distinguished name (DN) for the certificate request. 
        /// Format: "/C=Country/ST=State/L=City/O=Organization/OU=Unit/CN=CommonName"</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any string parameter is empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// string subject = "/C=US/ST=CA/L=San Francisco/O=MyCompany/CN=example.com";
        /// OpenSslFacade.GenerateCertificateSigningRequest("private_key.pem", "request.csr", subject);
        /// </code>
        /// </example>
        /// </summary>
        public static void GenerateCertificateSigningRequest(string keyPath, string outputPath, string subject)
        {
            OpenSLLWrapper.GenerateCertificateSigningRequest(keyPath, outputPath, subject);
        }

        /// <summary>
        /// Asynchronously create a Certificate Signing Request (CSR) in PEM format using the provided private key PEM file and subject.
        /// This method provides the same functionality as <see cref="GenerateCertificateSigningRequest(string, string, string)"/>
        /// but with asynchronous execution and cancellation support.
        /// </summary>
        /// <param name="keyPath">Path to the private key PEM file. Must not be null or empty.</param>
        /// <param name="outputPath">Path where the CSR PEM file will be written. Must not be null or empty.</param>
        /// <param name="subject">The subject distinguished name (DN) for the certificate request.</param>
        /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any string parameter is empty.</exception>
        /// <exception cref="OperationCanceledException">Thrown when the operation is canceled via <paramref name="cancellationToken"/>.</exception>
        public static Task GenerateCertificateSigningRequestAsync(string keyPath, string outputPath, string subject, CancellationToken cancellationToken = default)
        {
            return OpenSLLWrapper.GenerateCertificateSigningRequestAsync(keyPath, outputPath, subject, cancellationToken);
        }

        /// <summary>
        /// Create a Certificate Signing Request (CSR) in PEM format from private key bytes and subject and return PEM bytes.
        /// This method allows for fully in-memory CSR generation without requiring filesystem access.
        /// </summary>
        /// <param name="privateKeyPem">The private key in PKCS#1 or PKCS#8 PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="subject">The subject distinguished name (DN) for the certificate request. 
        /// Format: "/C=Country/ST=State/L=City/O=Organization/OU=Unit/CN=CommonName"</param>
        /// <returns>A byte array containing the CSR in PEM format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="privateKeyPem"/> is empty or <paramref name="subject"/> is empty.</exception>
        /// <example>
        /// <code>
        /// byte[] keyBytes = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// string subject = "/C=US/CN=example.com";
        /// byte[] csrBytes = OpenSslFacade.GenerateCertificateSigningRequestBytes(keyBytes, subject);
        /// </code>
        /// </example>
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
