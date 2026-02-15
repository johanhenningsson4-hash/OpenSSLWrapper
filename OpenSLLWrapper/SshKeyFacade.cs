using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Facade for SSH key format operations including conversions between PEM and SSH formats.
    /// Provides support for OpenSSH public/private key formats and interoperability with SSH clients.
    /// </summary>
    /// <remarks>
    /// This facade handles SSH key operations such as:
    /// - Converting RSA public keys to OpenSSH format (ssh-rsa)
    /// - Converting OpenSSH public keys back to PEM format
    /// - Converting RSA private keys to OpenSSH private key format
    /// - Supporting SSH key comments and metadata
    /// All methods follow the library's pattern of providing file, stream, and byte array overloads.
    /// OpenSSH format is widely used by SSH clients like OpenSSH, PuTTY, and cloud providers.
    /// </remarks>
    public static class SshKeyFacade
    {
        /// <summary>
        /// Convert an RSA public key from PEM format to OpenSSH format (ssh-rsa).
        /// The resulting SSH public key can be used in ~/.ssh/authorized_keys files.
        /// </summary>
        /// <param name="publicKeyPemPath">Path to the RSA public key PEM file. Must not be null or empty.</param>
        /// <param name="comment">Optional comment to append to the SSH public key (e.g., user@hostname). Can be null or empty.</param>
        /// <returns>A string containing the SSH public key in OpenSSH format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="publicKeyPemPath"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="publicKeyPemPath"/> is empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the public key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Convert PEM public key to SSH format
        /// string sshPublicKey = SshKeyFacade.ConvertPemToSshPublicKey(
        ///     "public_key.pem", 
        ///     "user@example.com");
        /// 
        /// // Write to authorized_keys file
        /// File.WriteAllText("~/.ssh/authorized_keys", sshPublicKey);
        /// Console.WriteLine(sshPublicKey);
        /// // Output: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABA... user@example.com
        /// </code>
        /// </example>
        public static string ConvertPemToSshPublicKey(string publicKeyPemPath, string comment = "")
        {
            if (publicKeyPemPath == null) throw new ArgumentNullException(nameof(publicKeyPemPath));
            if (string.IsNullOrWhiteSpace(publicKeyPemPath)) throw new ArgumentException("Public key path cannot be empty.", nameof(publicKeyPemPath));

            byte[] publicKeyBytes = File.ReadAllBytes(publicKeyPemPath);
            return ConvertPemToSshPublicKey(publicKeyBytes, comment);
        }

        /// <summary>
        /// Convert an RSA public key from PEM bytes to OpenSSH format (ssh-rsa).
        /// This method allows for in-memory SSH key conversion without requiring filesystem access.
        /// </summary>
        /// <param name="publicKeyPem">The RSA public key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="comment">Optional comment to append to the SSH public key (e.g., user@hostname). Can be null or empty.</param>
        /// <returns>A string containing the SSH public key in OpenSSH format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="publicKeyPem"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="publicKeyPem"/> is empty.</exception>
        /// <example>
        /// <code>
        /// // Generate key and convert to SSH format in memory
        /// byte[] privateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// byte[] publicKey = OpenSslFacade.ExportPublicKeyPemFromPrivateKeyBytes(privateKey);
        /// 
        /// string sshPublicKey = SshKeyFacade.ConvertPemToSshPublicKey(
        ///     publicKey, 
        ///     "generated@localhost");
        /// 
        /// Console.WriteLine(sshPublicKey);
        /// </code>
        /// </example>
        public static string ConvertPemToSshPublicKey(byte[] publicKeyPem, string comment = "")
        {
            if (publicKeyPem == null) throw new ArgumentNullException(nameof(publicKeyPem));
            if (publicKeyPem.Length == 0) throw new ArgumentException("Public key PEM cannot be empty.", nameof(publicKeyPem));

            return OpenSLLWrapper.ConvertPemToSshPublicKey(publicKeyPem, comment ?? "");
        }

        /// <summary>
        /// Convert an OpenSSH public key back to PEM format.
        /// This allows conversion from SSH authorized_keys format back to standard PEM format.
        /// </summary>
        /// <param name="sshPublicKey">The SSH public key string (e.g., "ssh-rsa AAAAB3NzaC1yc2E... comment"). Must not be null or empty.</param>
        /// <returns>A byte array containing the public key in PEM format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sshPublicKey"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="sshPublicKey"/> is empty or invalid format.</exception>
        /// <example>
        /// <code>
        /// // Parse SSH public key from authorized_keys
        /// string sshKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDH... user@example.com";
        /// byte[] pemBytes = SshKeyFacade.ConvertSshPublicKeyToPem(sshKey);
        /// 
        /// // Write as PEM file
        /// File.WriteAllBytes("converted_public_key.pem", pemBytes);
        /// 
        /// string pemString = Encoding.UTF8.GetString(pemBytes);
        /// Console.WriteLine(pemString);
        /// // Output: -----BEGIN PUBLIC KEY-----
        /// //         MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...
        /// //         -----END PUBLIC KEY-----
        /// </code>
        /// </example>
        public static byte[] ConvertSshPublicKeyToPem(string sshPublicKey)
        {
            if (sshPublicKey == null) throw new ArgumentNullException(nameof(sshPublicKey));
            if (string.IsNullOrWhiteSpace(sshPublicKey)) throw new ArgumentException("SSH public key cannot be empty.", nameof(sshPublicKey));

            return OpenSLLWrapper.ConvertSshPublicKeyToPem(sshPublicKey);
        }

        /// <summary>
        /// Convert an RSA private key from PEM format to OpenSSH private key format.
        /// The resulting private key can be used with SSH clients and supports optional passphrase protection.
        /// </summary>
        /// <param name="privateKeyPemPath">Path to the RSA private key PEM file. Must not be null or empty.</param>
        /// <param name="outputPath">Path where the OpenSSH private key will be written. Must not be null or empty.</param>
        /// <param name="passphrase">Optional passphrase to encrypt the OpenSSH private key. Can be null for unencrypted keys.</param>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any string parameter is empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Convert PEM private key to OpenSSH format with passphrase
        /// SshKeyFacade.ConvertPemToOpenSshPrivateKey(
        ///     "rsa_private_key.pem", 
        ///     "id_rsa", 
        ///     "secure_passphrase");
        /// 
        /// // The output file can be used with ssh-keygen, ssh-agent, etc.
        /// // ssh-keygen -y -f id_rsa > id_rsa.pub
        /// </code>
        /// </example>
        public static void ConvertPemToOpenSshPrivateKey(
            string privateKeyPemPath, 
            string outputPath, 
            string passphrase = null)
        {
            if (privateKeyPemPath == null) throw new ArgumentNullException(nameof(privateKeyPemPath));
            if (string.IsNullOrWhiteSpace(privateKeyPemPath)) throw new ArgumentException("Private key path cannot be empty.", nameof(privateKeyPemPath));
            if (outputPath == null) throw new ArgumentNullException(nameof(outputPath));
            if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException("Output path cannot be empty.", nameof(outputPath));

            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyPemPath);
            byte[] sshPrivateKeyBytes = ConvertPemToOpenSshPrivateKey(privateKeyBytes, passphrase);
            File.WriteAllBytes(outputPath, sshPrivateKeyBytes);
        }

        /// <summary>
        /// Convert an RSA private key from PEM bytes to OpenSSH private key format.
        /// This method allows for in-memory SSH private key conversion without requiring filesystem access.
        /// </summary>
        /// <param name="privateKeyPem">The RSA private key in PEM format as a byte array. Must not be null or empty.</param>
        /// <param name="passphrase">Optional passphrase to encrypt the OpenSSH private key. Can be null for unencrypted keys.</param>
        /// <returns>A byte array containing the private key in OpenSSH format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="privateKeyPem"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="privateKeyPem"/> is empty.</exception>
        /// <example>
        /// <code>
        /// // Generate and convert private key to OpenSSH format in memory
        /// byte[] pemPrivateKey = OpenSslFacade.GenerateRsaPrivateKeyBytes(2048);
        /// byte[] sshPrivateKey = SshKeyFacade.ConvertPemToOpenSshPrivateKey(
        ///     pemPrivateKey, 
        ///     "my_secure_passphrase");
        /// 
        /// // Write to SSH directory
        /// File.WriteAllBytes("~/.ssh/id_rsa", sshPrivateKey);
        /// </code>
        /// </example>
        public static byte[] ConvertPemToOpenSshPrivateKey(byte[] privateKeyPem, string passphrase = null)
        {
            if (privateKeyPem == null) throw new ArgumentNullException(nameof(privateKeyPem));
            if (privateKeyPem.Length == 0) throw new ArgumentException("Private key PEM cannot be empty.", nameof(privateKeyPem));

            return OpenSLLWrapper.ConvertPemToOpenSshPrivateKey(privateKeyPem, passphrase);
        }

        /// <summary>
        /// Convert an OpenSSH private key back to PEM format.
        /// This allows conversion from OpenSSH format back to standard PEM format, with passphrase support.
        /// </summary>
        /// <param name="sshPrivateKeyPath">Path to the OpenSSH private key file. Must not be null or empty.</param>
        /// <param name="outputPath">Path where the PEM private key will be written. Must not be null or empty.</param>
        /// <param name="passphrase">Passphrase for the encrypted OpenSSH private key. Can be null if the key is unencrypted.</param>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any string parameter is empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the SSH private key file does not exist.</exception>
        /// <example>
        /// <code>
        /// // Convert OpenSSH private key back to PEM
        /// SshKeyFacade.ConvertOpenSshPrivateKeyToPem(
        ///     "id_rsa", 
        ///     "converted_private_key.pem", 
        ///     "passphrase_if_encrypted");
        /// 
        /// // The output can be used with OpenSSL and other PEM-based tools
        /// </code>
        /// </example>
        public static void ConvertOpenSshPrivateKeyToPem(
            string sshPrivateKeyPath, 
            string outputPath, 
            string passphrase = null)
        {
            if (sshPrivateKeyPath == null) throw new ArgumentNullException(nameof(sshPrivateKeyPath));
            if (string.IsNullOrWhiteSpace(sshPrivateKeyPath)) throw new ArgumentException("SSH private key path cannot be empty.", nameof(sshPrivateKeyPath));
            if (outputPath == null) throw new ArgumentNullException(nameof(outputPath));
            if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException("Output path cannot be empty.", nameof(outputPath));

            byte[] sshPrivateKeyBytes = File.ReadAllBytes(sshPrivateKeyPath);
            byte[] pemPrivateKeyBytes = ConvertOpenSshPrivateKeyToPem(sshPrivateKeyBytes, passphrase);
            File.WriteAllBytes(outputPath, pemPrivateKeyBytes);
        }

        /// <summary>
        /// Convert an OpenSSH private key to PEM format using byte arrays for in-memory processing.
        /// This method provides full in-memory SSH private key conversion without requiring filesystem access.
        /// </summary>
        /// <param name="sshPrivateKey">The OpenSSH private key as a byte array. Must not be null or empty.</param>
        /// <param name="passphrase">Passphrase for the encrypted OpenSSH private key. Can be null if the key is unencrypted.</param>
        /// <returns>A byte array containing the private key in PEM format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sshPrivateKey"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="sshPrivateKey"/> is empty.</exception>
        /// <example>
        /// <code>
        /// // Convert SSH private key in memory
        /// byte[] sshKey = File.ReadAllBytes("id_rsa");
        /// byte[] pemKey = SshKeyFacade.ConvertOpenSshPrivateKeyToPem(sshKey, "passphrase");
        /// 
        /// string pemString = Encoding.UTF8.GetString(pemKey);
        /// Console.WriteLine(pemString);
        /// // Output: -----BEGIN RSA PRIVATE KEY-----
        /// //         MIIEpAIBAAKCAQEAxGH7...
        /// //         -----END RSA PRIVATE KEY-----
        /// </code>
        /// </example>
        public static byte[] ConvertOpenSshPrivateKeyToPem(byte[] sshPrivateKey, string passphrase = null)
        {
            if (sshPrivateKey == null) throw new ArgumentNullException(nameof(sshPrivateKey));
            if (sshPrivateKey.Length == 0) throw new ArgumentException("SSH private key cannot be empty.", nameof(sshPrivateKey));

            return OpenSLLWrapper.ConvertOpenSshPrivateKeyToPem(sshPrivateKey, passphrase);
        }

        /// <summary>
        /// Extract the comment from an SSH public key string.
        /// SSH public keys often contain comments (typically user@hostname) that can be extracted.
        /// </summary>
        /// <param name="sshPublicKey">The SSH public key string. Must not be null or empty.</param>
        /// <returns>The comment portion of the SSH public key, or empty string if no comment exists.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sshPublicKey"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="sshPublicKey"/> is empty.</exception>
        /// <example>
        /// <code>
        /// // Extract comment from SSH public key
        /// string sshKey = "ssh-rsa AAAAB3NzaC1yc2E... user@example.com";
        /// string comment = SshKeyFacade.ExtractSshPublicKeyComment(sshKey);
        /// Console.WriteLine($"Key comment: {comment}"); // Output: user@example.com
        /// </code>
        /// </example>
        public static string ExtractSshPublicKeyComment(string sshPublicKey)
        {
            if (sshPublicKey == null) throw new ArgumentNullException(nameof(sshPublicKey));
            if (string.IsNullOrWhiteSpace(sshPublicKey)) throw new ArgumentException("SSH public key cannot be empty.", nameof(sshPublicKey));

            return OpenSLLWrapper.ExtractSshPublicKeyComment(sshPublicKey);
        }

        /// <summary>
        /// Validate that a string is a properly formatted SSH public key.
        /// This checks the format and structure without verifying cryptographic validity.
        /// </summary>
        /// <param name="sshPublicKey">The SSH public key string to validate. Must not be null.</param>
        /// <returns>A SshKeyValidationResult indicating whether the key format is valid and any issues found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sshPublicKey"/> is null.</exception>
        /// <example>
        /// <code>
        /// // Validate SSH public key format
        /// string sshKey = "ssh-rsa AAAAB3NzaC1yc2E... user@example.com";
        /// var result = SshKeyFacade.ValidateSshPublicKeyFormat(sshKey);
        /// 
        /// if (result.IsValid)
        /// {
        ///     Console.WriteLine($"Valid SSH key: {result.KeyType}, {result.KeyLength} bits");
        /// }
        /// else
        /// {
        ///     Console.WriteLine($"Invalid SSH key: {result.ErrorMessage}");
        /// }
        /// </code>
        /// </example>
        public static SshKeyValidationResult ValidateSshPublicKeyFormat(string sshPublicKey)
        {
            if (sshPublicKey == null) throw new ArgumentNullException(nameof(sshPublicKey));

            return OpenSLLWrapper.ValidateSshPublicKeyFormat(sshPublicKey);
        }

        /// <summary>
        /// Generate an SSH key pair (public and private) in OpenSSH format.
        /// This is a convenience method that generates an RSA key pair and converts it to SSH format.
        /// </summary>
        /// <param name="keySize">RSA key size in bits. Common values are 2048, 3072, and 4096. Default is 2048.</param>
        /// <param name="comment">Optional comment for the SSH public key (e.g., user@hostname). Can be null or empty.</param>
        /// <param name="privateKeyPassphrase">Optional passphrase to encrypt the SSH private key. Can be null for unencrypted keys.</param>
        /// <returns>An SshKeyPair containing the public key (SSH format) and private key (OpenSSH format).</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="keySize"/> is invalid.</exception>
        /// <example>
        /// <code>
        /// // Generate SSH key pair
        /// var keyPair = SshKeyFacade.GenerateSshKeyPair(
        ///     keySize: 2048,
        ///     comment: "user@workstation",
        ///     privateKeyPassphrase: "secure_passphrase");
        /// 
        /// // Save to SSH directory
        /// File.WriteAllText("~/.ssh/id_rsa.pub", keyPair.PublicKey);
        /// File.WriteAllBytes("~/.ssh/id_rsa", keyPair.PrivateKeyBytes);
        /// 
        /// Console.WriteLine($"Generated SSH key pair:");
        /// Console.WriteLine($"Public key: {keyPair.PublicKey}");
        /// Console.WriteLine($"Private key length: {keyPair.PrivateKeyBytes.Length} bytes");
        /// </code>
        /// </example>
        public static SshKeyPair GenerateSshKeyPair(
            int keySize = 2048, 
            string comment = "", 
            string privateKeyPassphrase = null)
        {
            if (keySize < 1024) throw new ArgumentException("Key size must be at least 1024 bits.", nameof(keySize));

            return OpenSLLWrapper.GenerateSshKeyPair(keySize, comment ?? "", privateKeyPassphrase);
        }
    }
}