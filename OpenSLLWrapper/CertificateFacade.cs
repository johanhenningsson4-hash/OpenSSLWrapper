using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Facade for X.509 certificate operations including creation, signing, and validation.
    /// Provides high-level certificate management functionality built on BouncyCastle.
    /// </summary>
    /// <remarks>
    /// This facade handles common certificate operations such as:
    /// - Creating self-signed certificates for development and testing
    /// - Signing Certificate Signing Requests (CSRs) to issue certificates
    /// - Converting between certificate formats (PEM, PFX, DER)
    /// - Basic certificate validation and chain verification
    /// All methods follow the library's pattern of providing file, stream, and byte array overloads.
    /// </remarks>
    public static class CertificateFacade
    {
        /// <summary>
        /// Create a self-signed X.509 certificate from a private key PEM file.
        /// The certificate will be valid for the specified duration and can be used for development/testing purposes.
        /// </summary>
        /// <param name="privateKeyPath">Path to the RSA private key PEM file. Must not be null or empty.</param>
        /// <param name="subjectName">The X.500 distinguished name for the certificate subject (e.g., "CN=example.com,O=MyOrg,C=US").</param>
        /// <param name="validityPeriod">How long the certificate should be valid (e.g., TimeSpan.FromDays(365)).</param>
        /// <param name="keyUsage">Intended key usage for the certificate. Default is DigitalSignature.</param>
        /// <returns>An X509Certificate2 object containing the self-signed certificate with private key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Create a self-signed certificate for testing
        /// var cert = CertificateFacade.CreateSelfSignedCertificate(
        ///     "private_key.pem", 
        ///     "CN=test.example.com,O=Test Corp,C=US",
        ///     TimeSpan.FromDays(365));
        /// 
        /// // Use the certificate
        /// Console.WriteLine($"Certificate subject: {cert.Subject}");
        /// Console.WriteLine($"Certificate expires: {cert.NotAfter}");
        /// </code>
        /// </example>
        public static X509Certificate2 CreateSelfSignedCertificate(
            string privateKeyPath, 
            string subjectName, 
            TimeSpan validityPeriod,
            X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature)
        {
            if (privateKeyPath == null) throw new ArgumentNullException(nameof(privateKeyPath));
            if (string.IsNullOrWhiteSpace(privateKeyPath)) throw new ArgumentException("Private key path cannot be empty.", nameof(privateKeyPath));
            if (subjectName == null) throw new ArgumentNullException(nameof(subjectName));
            if (string.IsNullOrWhiteSpace(subjectName)) throw new ArgumentException("Subject name cannot be empty.", nameof(subjectName));
            if (validityPeriod <= TimeSpan.Zero) throw new ArgumentException("Validity period must be positive.", nameof(validityPeriod));

            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyPath);
            return CreateSelfSignedCertificate(privateKeyBytes, subjectName, validityPeriod, keyUsage);
        }

        /// <summary>
        /// Create a self-signed X.509 certificate from private key bytes.
        /// This method allows for in-memory certificate creation without filesystem access.
        /// </summary>
        /// <param name="privateKeyPem">The RSA private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="subjectName">The X.500 distinguished name for the certificate subject.</param>
        /// <param name="validityPeriod">How long the certificate should be valid.</param>
        /// <param name="keyUsage">Intended key usage for the certificate. Default is DigitalSignature.</param>
        /// <returns>An X509Certificate2 object containing the self-signed certificate with private key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Generate key and create certificate in memory
        /// byte[] privateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// var cert = CertificateFacade.CreateSelfSignedCertificate(
        ///     privateKey, 
        ///     "CN=api.example.com",
        ///     TimeSpan.FromYears(1));
        /// </code>
        /// </example>
        public static X509Certificate2 CreateSelfSignedCertificate(
            byte[] privateKeyPem, 
            string subjectName, 
            TimeSpan validityPeriod,
            X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature)
        {
            return OpenSLLWrapper.CreateSelfSignedCertificate(privateKeyPem, subjectName, validityPeriod, keyUsage);
        }

        /// <summary>
        /// Sign a Certificate Signing Request (CSR) to create a certificate issued by a Certificate Authority.
        /// This method takes a CSR and signs it with a CA's private key to produce a signed certificate.
        /// </summary>
        /// <param name="csrPath">Path to the CSR PEM file to be signed. Must not be null or empty.</param>
        /// <param name="caPrivateKeyPath">Path to the CA's private key PEM file. Must not be null or empty.</param>
        /// <param name="caCertificatePath">Path to the CA's certificate PEM file. Must not be null or empty.</param>
        /// <param name="validityPeriod">How long the issued certificate should be valid.</param>
        /// <param name="serialNumber">Certificate serial number. If null, a random serial number is generated.</param>
        /// <returns>An X509Certificate2 object containing the signed certificate.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when any required file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Sign a CSR to issue a certificate
        /// var issuedCert = CertificateFacade.SignCertificateRequest(
        ///     "client.csr",
        ///     "ca_private_key.pem",
        ///     "ca_certificate.pem",
        ///     TimeSpan.FromDays(90));
        /// 
        /// // Save the issued certificate
        /// File.WriteAllBytes("client_certificate.pem", issuedCert.RawData);
        /// </code>
        /// </example>
        public static X509Certificate2 SignCertificateRequest(
            string csrPath,
            string caPrivateKeyPath, 
            string caCertificatePath,
            TimeSpan validityPeriod,
            byte[] serialNumber = null)
        {
            if (csrPath == null) throw new ArgumentNullException(nameof(csrPath));
            if (string.IsNullOrWhiteSpace(csrPath)) throw new ArgumentException("CSR path cannot be empty.", nameof(csrPath));
            if (caPrivateKeyPath == null) throw new ArgumentNullException(nameof(caPrivateKeyPath));
            if (string.IsNullOrWhiteSpace(caPrivateKeyPath)) throw new ArgumentException("CA private key path cannot be empty.", nameof(caPrivateKeyPath));
            if (caCertificatePath == null) throw new ArgumentNullException(nameof(caCertificatePath));
            if (string.IsNullOrWhiteSpace(caCertificatePath)) throw new ArgumentException("CA certificate path cannot be empty.", nameof(caCertificatePath));

            byte[] csrBytes = File.ReadAllBytes(csrPath);
            byte[] caPrivateKeyBytes = File.ReadAllBytes(caPrivateKeyPath);
            byte[] caCertificateBytes = File.ReadAllBytes(caCertificatePath);

            return SignCertificateRequest(csrBytes, caPrivateKeyBytes, caCertificateBytes, validityPeriod, serialNumber);
        }

        /// <summary>
        /// Sign a Certificate Signing Request (CSR) using byte arrays for in-memory processing.
        /// This method provides full in-memory certificate signing without requiring filesystem access.
        /// </summary>
        /// <param name="csrPem">The CSR in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="caPrivateKeyPem">The CA's private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="caCertificatePem">The CA's certificate in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="validityPeriod">How long the issued certificate should be valid.</param>
        /// <param name="serialNumber">Certificate serial number. If null, a random serial number is generated.</param>
        /// <returns>An X509Certificate2 object containing the signed certificate.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid or empty.</exception>
        /// <example>
        /// <code>
        /// // Sign CSR in memory
        /// byte[] csr = OpenSslFacade.GenerateCertificateSigningRequestBytes(clientKey, "CN=client.example.com");
        /// byte[] caKey = File.ReadAllBytes("ca_private_key.pem");
        /// byte[] caCert = File.ReadAllBytes("ca_certificate.pem");
        /// 
        /// var signedCert = CertificateFacade.SignCertificateRequest(
        ///     csr, caKey, caCert, TimeSpan.FromDays(30));
        /// </code>
        /// </example>
        public static X509Certificate2 SignCertificateRequest(
            byte[] csrPem,
            byte[] caPrivateKeyPem, 
            byte[] caCertificatePem,
            TimeSpan validityPeriod,
            byte[] serialNumber = null)
        {
            return OpenSLLWrapper.SignCertificateRequest(csrPem, caPrivateKeyPem, caCertificatePem, validityPeriod, serialNumber);
        }

        /// <summary>
        /// Convert a certificate and private key in PEM format to a PFX (PKCS#12) file.
        /// This creates a password-protected container that includes both the certificate and its private key.
        /// </summary>
        /// <param name="certificatePemPath">Path to the certificate PEM file. Must not be null or empty.</param>
        /// <param name="privateKeyPemPath">Path to the private key PEM file. Must not be null or empty.</param>
        /// <param name="pfxOutputPath">Path where the PFX file will be written. Must not be null or empty.</param>
        /// <param name="password">Password to protect the PFX file. Must not be null or empty.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any string parameter is empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when any input file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Convert PEM certificate + key to PFX for Windows usage
        /// CertificateFacade.ConvertPemToPfx(
        ///     "certificate.pem", 
        ///     "private_key.pem", 
        ///     "certificate.pfx", 
        ///     "securePassword123");
        /// </code>
        /// </example>
        public static void ConvertPemToPfx(
            string certificatePemPath, 
            string privateKeyPemPath, 
            string pfxOutputPath, 
            string password)
        {
            if (certificatePemPath == null) throw new ArgumentNullException(nameof(certificatePemPath));
            if (string.IsNullOrWhiteSpace(certificatePemPath)) throw new ArgumentException("Certificate path cannot be empty.", nameof(certificatePemPath));
            if (privateKeyPemPath == null) throw new ArgumentNullException(nameof(privateKeyPemPath));
            if (string.IsNullOrWhiteSpace(privateKeyPemPath)) throw new ArgumentException("Private key path cannot be empty.", nameof(privateKeyPemPath));
            if (pfxOutputPath == null) throw new ArgumentNullException(nameof(pfxOutputPath));
            if (string.IsNullOrWhiteSpace(pfxOutputPath)) throw new ArgumentException("PFX output path cannot be empty.", nameof(pfxOutputPath));
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password cannot be empty.", nameof(password));

            byte[] certificateBytes = File.ReadAllBytes(certificatePemPath);
            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyPemPath);
            
            byte[] pfxBytes = ConvertPemToPfx(certificateBytes, privateKeyBytes, password);
            File.WriteAllBytes(pfxOutputPath, pfxBytes);
        }

        /// <summary>
        /// Convert a certificate and private key in PEM format to PFX (PKCS#12) bytes.
        /// This method provides in-memory conversion without requiring filesystem access.
        /// </summary>
        /// <param name="certificatePem">The certificate in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="privateKeyPem">The private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="password">Password to protect the PFX container. Must not be null or empty.</param>
        /// <returns>A byte array containing the PFX data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any parameter is empty.</exception>
        /// <example>
        /// <code>
        /// // Create PFX in memory
        /// byte[] cert = File.ReadAllBytes("certificate.pem");
        /// byte[] key = File.ReadAllBytes("private_key.pem");
        /// byte[] pfxData = CertificateFacade.ConvertPemToPfx(cert, key, "password");
        /// 
        /// // Load as X509Certificate2
        /// var certificate = new X509Certificate2(pfxData, "password", X509KeyStorageFlags.Exportable);
        /// </code>
        /// </example>
        public static byte[] ConvertPemToPfx(
            byte[] certificatePem, 
            byte[] privateKeyPem, 
            string password)
        {
            return OpenSLLWrapper.ConvertPemToPfx(certificatePem, privateKeyPem, password);
        }

        /// <summary>
        /// Convert a PFX (PKCS#12) file to separate PEM certificate and private key files.
        /// This extracts the certificate and private key from a password-protected PFX container.
        /// </summary>
        /// <param name="pfxPath">Path to the PFX file. Must not be null or empty.</param>
        /// <param name="password">Password for the PFX file. Must not be null.</param>
        /// <param name="certificateOutputPath">Path where the certificate PEM will be written. Must not be null or empty.</param>
        /// <param name="privateKeyOutputPath">Path where the private key PEM will be written. Must not be null or empty.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any string parameter is empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the PFX file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Extract certificate and key from PFX
        /// CertificateFacade.ConvertPfxToPem(
        ///     "certificate.pfx", 
        ///     "password123", 
        ///     "extracted_cert.pem", 
        ///     "extracted_key.pem");
        /// </code>
        /// </example>
        public static void ConvertPfxToPem(
            string pfxPath, 
            string password, 
            string certificateOutputPath, 
            string privateKeyOutputPath)
        {
            if (pfxPath == null) throw new ArgumentNullException(nameof(pfxPath));
            if (string.IsNullOrWhiteSpace(pfxPath)) throw new ArgumentException("PFX path cannot be empty.", nameof(pfxPath));
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (certificateOutputPath == null) throw new ArgumentNullException(nameof(certificateOutputPath));
            if (string.IsNullOrWhiteSpace(certificateOutputPath)) throw new ArgumentException("Certificate output path cannot be empty.", nameof(certificateOutputPath));
            if (privateKeyOutputPath == null) throw new ArgumentNullException(nameof(privateKeyOutputPath));
            if (string.IsNullOrWhiteSpace(privateKeyOutputPath)) throw new ArgumentException("Private key output path cannot be empty.", nameof(privateKeyOutputPath));

            byte[] pfxBytes = File.ReadAllBytes(pfxPath);
            var (certificatePem, privateKeyPem) = ConvertPfxToPem(pfxBytes, password);
            
            File.WriteAllBytes(certificateOutputPath, certificatePem);
            File.WriteAllBytes(privateKeyOutputPath, privateKeyPem);
        }

        /// <summary>
        /// Convert PFX (PKCS#12) bytes to separate PEM certificate and private key bytes.
        /// This method provides in-memory conversion without requiring filesystem access.
        /// </summary>
        /// <param name="pfxData">The PFX data as a byte array. Must not be null or empty.</param>
        /// <param name="password">Password for the PFX container. Must not be null.</param>
        /// <returns>A tuple containing the certificate PEM bytes and private key PEM bytes.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when pfxData is empty.</exception>
        /// <example>
        /// <code>
        /// // Extract from PFX in memory
        /// byte[] pfxData = File.ReadAllBytes("certificate.pfx");
        /// var (certPem, keyPem) = CertificateFacade.ConvertPfxToPem(pfxData, "password");
        /// 
        /// Console.WriteLine($"Certificate: {Encoding.UTF8.GetString(certPem)}");
        /// </code>
        /// </example>
        public static (byte[] certificatePem, byte[] privateKeyPem) ConvertPfxToPem(
            byte[] pfxData, 
            string password)
        {
            return OpenSLLWrapper.ConvertPfxToPem(pfxData, password);
        }

        /// <summary>
        /// Validate a certificate against a collection of trusted root certificates.
        /// This performs basic certificate chain validation including signature verification and validity period checks.
        /// </summary>
        /// <param name="certificate">The certificate to validate. Must not be null.</param>
        /// <param name="trustedRoots">Collection of trusted root certificates for chain validation. Must not be null.</param>
        /// <param name="checkRevocation">Whether to check for certificate revocation. Default is false.</param>
        /// <returns>A CertificateValidationResult containing validation status and any errors.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <example>
        /// <code>
        /// // Validate a certificate chain
        /// var cert = new X509Certificate2("server_cert.pem");
        /// var trustedRoots = new X509Certificate2Collection();
        /// trustedRoots.Import("ca_cert.pem");
        /// 
        /// var result = CertificateFacade.ValidateCertificate(cert, trustedRoots);
        /// if (result.IsValid)
        /// {
        ///     Console.WriteLine("Certificate is valid");
        /// }
        /// else
        /// {
        ///     Console.WriteLine($"Certificate validation failed: {result.ErrorMessage}");
        /// }
        /// </code>
        /// </example>
        public static CertificateValidationResult ValidateCertificate(
            X509Certificate2 certificate, 
            X509Certificate2Collection trustedRoots,
            bool checkRevocation = false)
        {
            return OpenSLLWrapper.ValidateCertificate(certificate, trustedRoots, checkRevocation);
        }
    }
}