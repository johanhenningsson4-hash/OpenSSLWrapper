using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
// BouncyCastle
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.IO.Pem;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace OpenSLLWrapper
{
    /// <summary>
    /// Core managed operations implemented with BouncyCastle.
    /// Public facade (OpenSslFacade) calls into these methods.
    /// </summary>
    public static class OpenSLLWrapper
    {
        // Cache parsed private keys by SHA-256 of the PEM bytes to avoid reparsing on each sign operation.
        private static readonly ConcurrentDictionary<string, AsymmetricKeyParameter> s_privateKeyCache = new ConcurrentDictionary<string, AsymmetricKeyParameter>();

        // Per-key signer pools to reuse ISigner instances. Key is "{keyHash}:{mode}" where mode is "pss" or "pkcs1".
        private static readonly ConcurrentDictionary<string, ConcurrentBag<ISigner>> s_signerPools = new ConcurrentDictionary<string, ConcurrentBag<ISigner>>();

        private static string ComputeSha256Base64(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(data));
            }
        }

        private static string SignWithPrivateKey(byte[] data, AsymmetricKeyParameter privateKey, bool usePss, string keyHash = null)
        {
            ISigner signer = null;
            string poolKey = null;
            if (!string.IsNullOrEmpty(keyHash))
            {
                poolKey = keyHash + ":" + (usePss ? "pss" : "pkcs1");
                var bag = s_signerPools.GetOrAdd(poolKey, _ => new ConcurrentBag<ISigner>());
                if (!bag.TryTake(out signer))
                {
                    signer = CreateNewSigner(usePss, privateKey);
                }
                else
                {
                    // Ensure signer is initialized for this key (re-init to be safe)
                    signer.Init(true, privateKey);
                }
            }
            else
            {
                signer = CreateNewSigner(usePss, privateKey);
            }

            try
            {
                signer.BlockUpdate(data, 0, data.Length);
                var sig = signer.GenerateSignature();
                return Convert.ToBase64String(sig);
            }
            finally
            {
                try
                {
                    signer.Reset();
                }
                catch
                {
                    // Ignore reset failures and don't return to pool
                    signer = null;
                }

                if (signer != null && poolKey != null)
                {
                    var bag = s_signerPools.GetOrAdd(poolKey, _ => new ConcurrentBag<ISigner>());
                    bag.Add(signer);
                }
            }
        }

        private static ISigner CreateNewSigner(bool usePss, AsymmetricKeyParameter privateKey)
        {
            if (!usePss)
            {
                var signer = SignerUtilities.GetSigner("SHA256withRSA");
                signer.Init(true, privateKey);
                return signer;
            }
            else
            {
                var digest = new Sha256Digest();
                var engine = new RsaEngine();
                var pss = new Org.BouncyCastle.Crypto.Signers.PssSigner(engine, digest, digest.GetDigestSize());
                pss.Init(true, privateKey);
                return pss;
            }
        }
        // -------------------- Key generation --------------------

        /// <summary>
        /// Generate an RSA private key and write it to a PEM file (PKCS#1 "RSA PRIVATE KEY").
        /// </summary>
        public static void GenerateRsaPrivateKey(string outputPath, int keySize = 4096)
        {
            if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException("outputPath must be provided", nameof(outputPath));
            if (keySize < 1024) throw new ArgumentOutOfRangeException(nameof(keySize));
            using (var fs = File.Create(outputPath))
                GenerateRsaPrivateKey(fs, keySize);
        }

        /// <summary>
        /// Generate an RSA private key and write PEM into the provided stream (left open).
        /// </summary>
        public static void GenerateRsaPrivateKey(Stream outputStream, int keySize = 4096)
        {
            if (outputStream == null) throw new ArgumentNullException(nameof(outputStream));
            if (keySize < 1024) throw new ArgumentOutOfRangeException(nameof(keySize));

            var gen = new RsaKeyPairGenerator();
            gen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();

            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true))
            {
                var pem = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                pem.WriteObject(kp.Private);
                sw.Flush();
            }
        }

        /// <summary>
        /// Generate RSA private key and return PEM bytes.
        /// </summary>
        public static byte[] GenerateRsaPrivateKeyBytes(int keySize = 4096)
        {
            using (var ms = new MemoryStream())
            {
                GenerateRsaPrivateKey(ms, keySize);
                return ms.ToArray();
            }
        }

        public static Task GenerateRsaPrivateKeyAsync(string outputPath, int keySize = 4096, CancellationToken cancellationToken = default)
            => Task.Run(() => GenerateRsaPrivateKey(outputPath, keySize), cancellationToken);

        // -------------------- CSR creation --------------------

        public static void GenerateCertificateSigningRequest(string keyPath, string outputPath, string subject)
        {
            if (string.IsNullOrWhiteSpace(keyPath)) throw new ArgumentException(nameof(keyPath));
            if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException(nameof(outputPath));
            using (var inFs = File.OpenRead(keyPath))
            using (var outFs = File.Create(outputPath))
                GenerateCertificateSigningRequest(inFs, outFs, subject);
        }

        public static void GenerateCertificateSigningRequest(Stream privateKeyPemStream, Stream outputStream, string subject)
        {
            if (privateKeyPemStream == null) throw new ArgumentNullException(nameof(privateKeyPemStream));
            if (outputStream == null) throw new ArgumentNullException(nameof(outputStream));
            if (string.IsNullOrWhiteSpace(subject)) throw new ArgumentException(nameof(subject));

            object keyObj;
            using (var sr = new StreamReader(privateKeyPemStream, Encoding.ASCII, false, 1024, leaveOpen: true))
            {
                var pr = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                keyObj = pr.ReadObject();
            }

            AsymmetricKeyParameter privateKey;
            AsymmetricKeyParameter publicKey;
            if (keyObj is AsymmetricCipherKeyPair pair)
            {
                privateKey = pair.Private;
                publicKey = pair.Public;
            }
            else if (keyObj is AsymmetricKeyParameter akp && akp.IsPrivate)
            {
                privateKey = akp;
                var rsaPriv = akp as RsaPrivateCrtKeyParameters;
                if (rsaPriv == null) throw new InvalidOperationException("Unsupported private key type");
                publicKey = new RsaKeyParameters(false, rsaPriv.Modulus, rsaPriv.PublicExponent);
            }
            else throw new InvalidOperationException("Unsupported key format");

            string subj = subject.Trim();
            if (subj.StartsWith("/"))
            {
                var parts = subj.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
                subj = string.Join(", ", parts);
            }

            var x509Name = new X509Name(subj);
            var csr = new Pkcs10CertificationRequest("SHA256WITHRSA", x509Name, publicKey, null, privateKey);
            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true))
            {
                var pem = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                pem.WriteObject(csr);
                sw.Flush();
            }
        }

        public static byte[] GenerateCertificateSigningRequestBytes(byte[] privateKeyPem, string subject)
        {
            if (privateKeyPem == null) throw new ArgumentNullException(nameof(privateKeyPem));
            using (var inMs = new MemoryStream(privateKeyPem))
            using (var outMs = new MemoryStream())
            {
                GenerateCertificateSigningRequest(inMs, outMs, subject);
                return outMs.ToArray();
            }
        }

        public static Task GenerateCertificateSigningRequestAsync(string keyPath, string outputPath, string subject, CancellationToken cancellationToken = default)
            => Task.Run(() => GenerateCertificateSigningRequest(keyPath, outputPath, subject), cancellationToken);

        // -------------------- Signing --------------------

        /// <summary>
        /// Sign raw data using a private key PEM stream. Returns base64 signature.
        /// Supports PKCS#1-v1_5 (default) and RSASSA-PSS if usePss=true.
        /// </summary>
        public static string SignChallengeData(byte[] data, Stream privateKeyPemStream, bool usePss = false)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (privateKeyPemStream == null) throw new ArgumentNullException(nameof(privateKeyPemStream));
            // Try to obtain the raw PEM bytes for caching. If we can get bytes, compute a key hash and reuse parsed key.
            byte[] keyBytes = null;
            try
            {
                if (privateKeyPemStream is MemoryStream ms)
                {
                    keyBytes = ms.ToArray();
                }
                else if (privateKeyPemStream.CanSeek)
                {
                    long origPos = privateKeyPemStream.Position;
                    privateKeyPemStream.Position = 0;
                    using (var tmp = new MemoryStream())
                    {
                        privateKeyPemStream.CopyTo(tmp);
                        keyBytes = tmp.ToArray();
                    }
                    privateKeyPemStream.Position = origPos;
                }
            }
            catch
            {
                // If any IO error occurs, fall back to parsing directly from the stream without caching.
                keyBytes = null;
            }

            AsymmetricKeyParameter privateKey = null;

            if (keyBytes != null)
            {
                string keyHash = ComputeSha256Base64(keyBytes);
                if (!s_privateKeyCache.TryGetValue(keyHash, out privateKey))
                {
                    // Parse and add to cache
                    using (var sr = new StreamReader(new MemoryStream(keyBytes), Encoding.ASCII, false, 1024, leaveOpen: true))
                    {
                        var pr = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                        var keyObj = pr.ReadObject();
                        if (keyObj is AsymmetricCipherKeyPair kp) privateKey = kp.Private;
                        else if (keyObj is AsymmetricKeyParameter akp && akp.IsPrivate) privateKey = akp;
                        else throw new InvalidOperationException("Unsupported private key format");
                    }

                    s_privateKeyCache.TryAdd(keyHash, privateKey);
                }
                else
                {
                    // nothing
                }
            }

            if (privateKey == null)
            {
                // Fallback: parse directly from provided stream (no caching)
                object keyObj;
                using (var sr = new StreamReader(privateKeyPemStream, Encoding.ASCII, false, 1024, leaveOpen: true))
                    keyObj = new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();

                if (keyObj is AsymmetricCipherKeyPair kp) privateKey = kp.Private;
                else if (keyObj is AsymmetricKeyParameter akp && akp.IsPrivate) privateKey = akp;
                else throw new InvalidOperationException("Unsupported private key format");
            }

            // If we have a key hash, pass it so signer pooling can be used
            string hashForPool = (keyBytes != null) ? ComputeSha256Base64(keyBytes) : null;
            return SignWithPrivateKey(data, privateKey, usePss, hashForPool);
        }

        public static string SignChallengeData(byte[] data, byte[] privateKeyPem, bool usePss = false)
        {
            if (privateKeyPem == null) throw new ArgumentNullException(nameof(privateKeyPem));
            using (var ms = new MemoryStream(privateKeyPem))
            {
                return SignChallengeData(data, ms, usePss);
            }
        }

        public static string SignBase64Challenge(string base64Challenge, string keyPath)
        {
            if (string.IsNullOrWhiteSpace(base64Challenge)) throw new ArgumentException(nameof(base64Challenge));
            if (string.IsNullOrWhiteSpace(keyPath)) throw new ArgumentException(nameof(keyPath));
            byte[] data = Convert.FromBase64String(base64Challenge);
            using (var fs = File.OpenRead(keyPath)) return SignChallengeData(data, fs, usePss: false);
        }

        public static Task<string> SignBase64ChallengeAsync(string base64Challenge, string keyPath, CancellationToken cancellationToken = default)
            => Task.Run(() => SignBase64Challenge(base64Challenge, keyPath), cancellationToken);

        // -------------------- Verification --------------------

        public static bool VerifyChallengeData(byte[] data, byte[] signature, Stream publicKeyPemStream, bool usePss = false)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (publicKeyPemStream == null) throw new ArgumentNullException(nameof(publicKeyPemStream));

            object keyObj;
            using (var sr = new StreamReader(publicKeyPemStream, Encoding.ASCII, false, 1024, leaveOpen: true))
                keyObj = new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();

            AsymmetricKeyParameter publicKey = null;
            if (keyObj is AsymmetricKeyParameter akp && !akp.IsPrivate) publicKey = akp;
            else if (keyObj is AsymmetricCipherKeyPair kp) publicKey = kp.Public;
            else if (keyObj is X509Certificate cert) publicKey = cert.GetPublicKey();
            else throw new InvalidOperationException("Unsupported public key format");

            if (!usePss)
            {
                var verifier = SignerUtilities.GetSigner("SHA256withRSA");
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(data, 0, data.Length);
                return verifier.VerifySignature(signature);
            }
            else
            {
                var digest = new Sha256Digest();
                var engine = new RsaEngine();
                var pss = new Org.BouncyCastle.Crypto.Signers.PssSigner(engine, digest, digest.GetDigestSize());
                pss.Init(false, publicKey);
                pss.BlockUpdate(data, 0, data.Length);
                return pss.VerifySignature(signature);
            }
        }

        public static bool VerifyChallengeData(byte[] data, byte[] signature, byte[] publicKeyPem, bool usePss = false)
        {
            if (publicKeyPem == null) throw new ArgumentNullException(nameof(publicKeyPem));
            using (var ms = new MemoryStream(publicKeyPem)) return VerifyChallengeData(data, signature, ms, usePss);
        }

        public static bool VerifyBase64Signature(string base64Challenge, string base64Signature, string publicKeyPath, bool usePss = false)
        {
            if (string.IsNullOrWhiteSpace(base64Challenge)) throw new ArgumentException(nameof(base64Challenge));
            if (string.IsNullOrWhiteSpace(base64Signature)) throw new ArgumentException(nameof(base64Signature));
            if (string.IsNullOrWhiteSpace(publicKeyPath)) throw new ArgumentException(nameof(publicKeyPath));
            byte[] data = Convert.FromBase64String(base64Challenge);
            byte[] sig = Convert.FromBase64String(base64Signature);
            using (var fs = File.OpenRead(publicKeyPath)) return VerifyChallengeData(data, sig, fs, usePss);
        }

        // -------------------- PKCS format conversions & public key export --------------------

        public static void ConvertPkcs1ToPkcs8Pem(string pkcs1Path, string pkcs8Path)
        {
            using (var inFs = File.OpenRead(pkcs1Path))
            using (var outFs = File.Create(pkcs8Path)) ConvertPkcs1ToPkcs8Pem(inFs, outFs);
        }

        public static void ConvertPkcs1ToPkcs8Pem(Stream pkcs1Stream, Stream outputStream)
        {
            object keyObj;
            using (var sr = new StreamReader(pkcs1Stream, Encoding.ASCII, false, 1024, leaveOpen: true)) keyObj = new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();
            AsymmetricKeyParameter privateKey = (keyObj is AsymmetricCipherKeyPair p) ? p.Private : keyObj as AsymmetricKeyParameter;
            if (privateKey == null || !privateKey.IsPrivate) throw new InvalidOperationException("Unsupported key format");
            var pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            var pkcs8 = pkInfo.ToAsn1Object().GetEncoded();
            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true)) new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(new Org.BouncyCastle.Utilities.IO.Pem.PemObject("PRIVATE KEY", pkcs8));
        }

        public static byte[] ConvertPkcs1ToPkcs8PemBytes(byte[] pkcs1Pem)
        {
            using (var inMs = new MemoryStream(pkcs1Pem))
            using (var outMs = new MemoryStream()) { ConvertPkcs1ToPkcs8Pem(inMs, outMs); return outMs.ToArray(); }
        }

        public static void ConvertPkcs8ToPkcs1Pem(string pkcs8Path, string pkcs1Path)
        {
            using (var inFs = File.OpenRead(pkcs8Path))
            using (var outFs = File.Create(pkcs1Path)) ConvertPkcs8ToPkcs1Pem(inFs, outFs);
        }

        public static void ConvertPkcs8ToPkcs1Pem(Stream pkcs8Stream, Stream outputStream)
        {
            object keyObj;
            using (var sr = new StreamReader(pkcs8Stream, Encoding.ASCII, false, 1024, leaveOpen: true)) keyObj = new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();
            AsymmetricKeyParameter privateKey = (keyObj is AsymmetricCipherKeyPair p) ? p.Private : keyObj as AsymmetricKeyParameter;
            if (privateKey == null || !privateKey.IsPrivate) throw new InvalidOperationException("Unsupported key format");
            var rsaPriv = privateKey as RsaPrivateCrtKeyParameters;
            if (rsaPriv == null) throw new InvalidOperationException("Not an RSA key");
            var rsaStruct = new RsaPrivateKeyStructure(rsaPriv.Modulus, rsaPriv.PublicExponent, rsaPriv.Exponent, rsaPriv.P, rsaPriv.Q, rsaPriv.DP, rsaPriv.DQ, rsaPriv.QInv);
            var pkcs1 = rsaStruct.ToAsn1Object().GetEncoded();
            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true)) new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(new Org.BouncyCastle.Utilities.IO.Pem.PemObject("RSA PRIVATE KEY", pkcs1));
        }

        public static byte[] ConvertPkcs8ToPkcs1PemBytes(byte[] pkcs8Pem)
        {
            using (var inMs = new MemoryStream(pkcs8Pem))
            using (var outMs = new MemoryStream()) { ConvertPkcs8ToPkcs1Pem(inMs, outMs); return outMs.ToArray(); }
        }

        public static void ExportPublicKeyPemFromPrivateKey(string keyPath, string outputPath)
        {
            using (var inFs = File.OpenRead(keyPath))
            using (var outFs = File.Create(outputPath)) ExportPublicKeyPemFromPrivateKey(inFs, outFs);
        }

        public static void ExportPublicKeyPemFromPrivateKey(Stream privateKeyPemStream, Stream outputStream)
        {
            object keyObj;
            using (var sr = new StreamReader(privateKeyPemStream, Encoding.ASCII, false, 1024, leaveOpen: true)) keyObj = new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();
            AsymmetricKeyParameter publicKey = null;
            if (keyObj is AsymmetricCipherKeyPair p) publicKey = p.Public;
            else if (keyObj is AsymmetricKeyParameter akp && akp.IsPrivate)
            {
                var rsa = akp as RsaPrivateCrtKeyParameters;
                if (rsa == null) throw new InvalidOperationException("Unsupported private key");
                publicKey = new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent);
            }
            else if (keyObj is AsymmetricKeyParameter akpub && !akpub.IsPrivate) publicKey = akpub;
            else throw new InvalidOperationException("Unsupported key format");
            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true)) new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(publicKey);
        }

        public static byte[] ExportPublicKeyPemFromPrivateKeyBytes(byte[] privateKeyPem)
        {
            using (var inMs = new MemoryStream(privateKeyPem))
            using (var outMs = new MemoryStream()) { ExportPublicKeyPemFromPrivateKey(inMs, outMs); return outMs.ToArray(); }
        }

        // -------------------- Safe storage helpers --------------------

        /// <summary>
        /// Write PEM bytes to a file and restrict filesystem ACL to the current user only.
        /// This avoids accidental world-readable private key files on multi-user systems.
        /// </summary>
        /// <param name="path">Path to write the PEM file.</param>
        /// <param name="pemBytes">PEM bytes to write.</param>
        public static void SavePemFileSecure(string path, byte[] pemBytes)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException(nameof(path));
            if (pemBytes == null) throw new ArgumentNullException(nameof(pemBytes));

            // Write file (overwrite)
            File.WriteAllBytes(path, pemBytes);

            try
            {
                // Build a restrictive ACL: remove inheritance and grant FullControl to the current user only
                var fileInfo = new FileInfo(path);
                var security = fileInfo.GetAccessControl();
                // Disable inheritance and remove existing rules
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                // Remove all existing rules
                var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule rule in rules)
                {
                    security.RemoveAccessRule(rule);
                }

                // Grant current user FullControl
                var sid = WindowsIdentity.GetCurrent().User;
                if (sid == null) throw new InvalidOperationException("Unable to get current user SID");
                var userRule = new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow);
                security.AddAccessRule(userRule);

                fileInfo.SetAccessControl(security);
            }
            catch (PlatformNotSupportedException)
            {
                // On non-Windows platforms or restricted environments, ignore ACL changes
            }
            catch (Exception)
            {
                // If ACL modification fails, do not crash; caller can choose to delete the file.
            }
        }

        /// <summary>
        /// Encrypt PEM bytes with a password using PBKDF2 (HMAC-SHA256) to derive keys and AES-CBC for confidentiality
        /// and HMAC-SHA256 for integrity (encrypt-then-MAC). Writes a binary blob containing: version(1)|salt(16)|iv(16)|ciphertext|hmac(32).
        /// </summary>
        public static void SavePemFileEncrypted(string path, byte[] pemBytes, string password, int iterations = 100_000)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException(nameof(path));
            if (pemBytes == null) throw new ArgumentNullException(nameof(pemBytes));
            if (string.IsNullOrEmpty(password)) throw new ArgumentException("password required", nameof(password));

            // salt and iv
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
                rng.GetBytes(iv);
            }

            // derive keys (32 bytes enc key, 32 bytes mac key)
            byte[] encKey, macKey;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                encKey = kdf.GetBytes(32);
                macKey = kdf.GetBytes(32);
            }

            byte[] cipher;
            using (var aes = new AesManaged { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
            {
                aes.Key = encKey;
                aes.IV = iv;
                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(pemBytes, 0, pemBytes.Length);
                    cs.FlushFinalBlock();
                    cipher = ms.ToArray();
                }
            }

            // build blob and compute HMAC
            using (var msAll = new MemoryStream())
            using (var hmac = new HMACSHA256(macKey))
            {
                msAll.WriteByte(0x01); // version
                msAll.Write(salt, 0, salt.Length);
                msAll.Write(iv, 0, iv.Length);
                msAll.Write(cipher, 0, cipher.Length);
                byte[] blobNoMac = msAll.ToArray();
                byte[] tag = hmac.ComputeHash(blobNoMac);
                using (var outFs = File.Create(path))
                {
                    outFs.Write(blobNoMac, 0, blobNoMac.Length);
                    outFs.Write(tag, 0, tag.Length);
                }
            }
        }

        /// <summary>
        /// Read a file produced by SavePemFileEncrypted and decrypt it using the provided password.
        /// </summary>
        public static byte[] LoadPemFileEncrypted(string path, string password, int iterations = 100_000)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException(nameof(path));
            if (!File.Exists(path)) throw new FileNotFoundException("File not found", path);
            if (string.IsNullOrEmpty(password)) throw new ArgumentException("password required", nameof(password));

            byte[] all = File.ReadAllBytes(path);
            if (all.Length < 1 + 16 + 16 + 32) throw new InvalidOperationException("File too small or corrupt");
            int pos = 0;
            byte version = all[pos++];
            if (version != 0x01) throw new InvalidOperationException("Unsupported blob version");
            byte[] salt = new byte[16]; Array.Copy(all, pos, salt, 0, 16); pos += 16;
            byte[] iv = new byte[16]; Array.Copy(all, pos, iv, 0, 16); pos += 16;
            int macLen = 32;
            int cipherLen = all.Length - pos - macLen;
            if (cipherLen <= 0) throw new InvalidOperationException("Invalid blob layout");
            byte[] cipher = new byte[cipherLen]; Array.Copy(all, pos, cipher, 0, cipherLen); pos += cipherLen;
            byte[] tag = new byte[macLen]; Array.Copy(all, pos, tag, 0, macLen);

            // derive keys
            byte[] encKey, macKey;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                encKey = kdf.GetBytes(32);
                macKey = kdf.GetBytes(32);
            }

            // verify HMAC
            byte[] blobNoMac = new byte[1 + salt.Length + iv.Length + cipher.Length];
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x01);
                ms.Write(salt, 0, salt.Length);
                ms.Write(iv, 0, iv.Length);
                ms.Write(cipher, 0, cipher.Length);
                blobNoMac = ms.ToArray();
            }
            using (var hmac = new HMACSHA256(macKey))
            {
                var expected = hmac.ComputeHash(blobNoMac);
                if (!CryptographicEquals(expected, tag)) throw new CryptographicException("HMAC validation failed");
            }

            // decrypt
            using (var aes = new AesManaged { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
            {
                aes.Key = encKey;
                aes.IV = iv;
                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(cipher))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var outMs = new MemoryStream())
                {
                    cs.CopyTo(outMs);
                    return outMs.ToArray();
                }
            }
        }

        private static bool CryptographicEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        /// <summary>
        /// Protect PEM bytes using Windows DPAPI (ProtectedData) and write the protected blob to disk.
        /// This helper is Windows-only and will throw <see cref="PlatformNotSupportedException"/> on non-Windows platforms.
        /// </summary>
        /// <param name="path">Path to write protected blob.</param>
        /// <param name="pemBytes">PEM bytes to protect/write.</param>
        /// <param name="forMachine">If true, protect for local machine; otherwise protect for current user.</param>
        public static void SavePemFileDpapiWindows(string path, byte[] pemBytes, bool forMachine = false)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException(nameof(path));
            if (pemBytes == null) throw new ArgumentNullException(nameof(pemBytes));
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) throw new PlatformNotSupportedException("DPAPI is supported only on Windows");

            var scope = forMachine ? System.Security.Cryptography.DataProtectionScope.LocalMachine : System.Security.Cryptography.DataProtectionScope.CurrentUser;
            byte[] protectedBytes = System.Security.Cryptography.ProtectedData.Protect(pemBytes, null, scope);
            File.WriteAllBytes(path, protectedBytes);
        }

        /// <summary>
        /// Read and unprotect a DPAPI-protected PEM file written with <see cref="SavePemFileDpapiWindows"/>.
        /// This helper is Windows-only and will throw <see cref="PlatformNotSupportedException"/> on non-Windows platforms.
        /// </summary>
        public static byte[] LoadPemFileDpapiWindows(string path, bool forMachine = false)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException(nameof(path));
            if (!File.Exists(path)) throw new FileNotFoundException("File not found", path);
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) throw new PlatformNotSupportedException("DPAPI is supported only on Windows");

            byte[] blob = File.ReadAllBytes(path);
            var scope = forMachine ? System.Security.Cryptography.DataProtectionScope.LocalMachine : System.Security.Cryptography.DataProtectionScope.CurrentUser;
            return System.Security.Cryptography.ProtectedData.Unprotect(blob, null, scope);
        }

        // --- Encrypted PKCS#8 support ---
        private class StringPasswordFinder : Org.BouncyCastle.OpenSsl.IPasswordFinder
        {
            private readonly char[] _pw;
            public StringPasswordFinder(string password) { _pw = password?.ToCharArray() ?? throw new ArgumentNullException(nameof(password)); }
            public char[] GetPassword() => (char[])_pw.Clone();
        }

        public static void ExportEncryptedPkcs8Pem(string inputPrivateKeyPath, string outputPkcs8Path, string password)
        {
            using (var inFs = File.OpenRead(inputPrivateKeyPath))
            using (var outFs = File.Create(outputPkcs8Path))
                ExportEncryptedPkcs8Pem(inFs, outFs, password);
        }

        public static void ExportEncryptedPkcs8Pem(Stream inputPrivateKeyStream, Stream outputStream, string password)
        {
            if (inputPrivateKeyStream == null) throw new ArgumentNullException(nameof(inputPrivateKeyStream));
            if (outputStream == null) throw new ArgumentNullException(nameof(outputStream));
            if (password == null) throw new ArgumentNullException(nameof(password));

            object keyObj;
            using (var sr = new StreamReader(inputPrivateKeyStream, Encoding.ASCII, false, 1024, leaveOpen: true))
                keyObj = new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();

            AsymmetricKeyParameter privateKey = null;
            if (keyObj is AsymmetricCipherKeyPair kp) privateKey = kp.Private;
            else if (keyObj is AsymmetricKeyParameter akp && akp.IsPrivate) privateKey = akp;
            else throw new InvalidOperationException("Unsupported private key format");

            var gen = new Org.BouncyCastle.OpenSsl.Pkcs8Generator(privateKey, Org.BouncyCastle.OpenSsl.Pkcs8Generator.PbeSha1_3DES);
            gen.Password = password.ToCharArray();

            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true))
            {
                new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(gen);
                sw.Flush();
            }
        }

        public static void ImportEncryptedPkcs8ToPkcs1Pem(string encryptedPkcs8Path, string password, string outputPkcs1Path)
        {
            using (var inFs = File.OpenRead(encryptedPkcs8Path))
            using (var outFs = File.Create(outputPkcs1Path))
                ImportEncryptedPkcs8ToPkcs1Pem(inFs, password, outFs);
        }

        public static void ImportEncryptedPkcs8ToPkcs1Pem(Stream encryptedPkcs8Stream, string password, Stream outputStream)
        {
            if (encryptedPkcs8Stream == null) throw new ArgumentNullException(nameof(encryptedPkcs8Stream));
            if (outputStream == null) throw new ArgumentNullException(nameof(outputStream));
            if (password == null) throw new ArgumentNullException(nameof(password));

            object keyObj;
            using (var sr = new StreamReader(encryptedPkcs8Stream, Encoding.ASCII, false, 1024, leaveOpen: true))
            {
                var pr = new Org.BouncyCastle.OpenSsl.PemReader(sr, new StringPasswordFinder(password));
                keyObj = pr.ReadObject();
            }

            AsymmetricKeyParameter privateKey = null;
            if (keyObj is AsymmetricCipherKeyPair kp) privateKey = kp.Private;
            else if (keyObj is AsymmetricKeyParameter akp && akp.IsPrivate) privateKey = akp;
            else throw new InvalidOperationException("Unsupported encrypted PKCS#8 format");

            using (var sw = new StreamWriter(outputStream, Encoding.ASCII, 1024, leaveOpen: true))
            {
                new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(privateKey);
                sw.Flush();
            }
        }

        public static Task ExportEncryptedPkcs8PemAsync(string inputPrivateKeyPath, string outputPkcs8Path, string password, CancellationToken cancellationToken = default)
            => Task.Run(() => ExportEncryptedPkcs8Pem(inputPrivateKeyPath, outputPkcs8Path, password), cancellationToken);

        public static Task ImportEncryptedPkcs8ToPkcs1PemAsync(string encryptedPkcs8Path, string password, string outputPkcs1Path, CancellationToken cancellationToken = default)
            => Task.Run(() => ImportEncryptedPkcs8ToPkcs1Pem(encryptedPkcs8Path, password, outputPkcs1Path), cancellationToken);
    }
}
