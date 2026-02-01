using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using OpenSLLWrapper;

namespace OpenSLLWrapper.Tests
{
    class Program
    {
        static int Main(string[] args)
        {
            try
            {
                string tmp = Path.Combine(Path.GetTempPath(), "opensllwrapper_test");
                if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                Directory.CreateDirectory(tmp);

                string privPath = Path.Combine(tmp, "private_key.pem");
                string pubPath = Path.Combine(tmp, "public_key.pem");
                string csrPath = Path.Combine(tmp, "example.csr");
                string pkcs8Path = Path.Combine(tmp, "private_key_pkcs8.pem");
                string pkcs1Roundtrip = Path.Combine(tmp, "private_key_roundtrip.pem");

                Console.WriteLine("Generating RSA private key...");
                OpenSLLWrapper.GenerateRsaPrivateKey(privPath, 2048);
                if (!File.Exists(privPath)) throw new Exception("private key not created");
                Console.WriteLine("Private key created: " + privPath);

                Console.WriteLine("Exporting public key...");
                OpenSLLWrapper.ExportPublicKeyPemFromPrivateKey(privPath, pubPath);
                if (!File.Exists(pubPath)) throw new Exception("public key not created");
                Console.WriteLine("Public key created: " + pubPath);

                Console.WriteLine("Generating CSR...");
                OpenSLLWrapper.GenerateCertificateSigningRequest(privPath, csrPath, "/C=US/ST=CA/L=San Francisco/O=Test/OU=Dev/CN=example.com");
                if (!File.Exists(csrPath)) throw new Exception("CSR not created");
                Console.WriteLine("CSR created: " + csrPath);

                Console.WriteLine("Signing challenge...");
                var challenge = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello world"));
                string signature = OpenSLLWrapper.SignBase64Challenge(challenge, privPath);
                if (string.IsNullOrWhiteSpace(signature)) throw new Exception("signature empty");
                Console.WriteLine("Signature (base64): " + signature.Substring(0, Math.Min(64, signature.Length)) + "...");

                Console.WriteLine("Converting PKCS#1 -> PKCS#8...");
                OpenSLLWrapper.ConvertPkcs1ToPkcs8Pem(privPath, pkcs8Path);
                if (!File.Exists(pkcs8Path)) throw new Exception("PKCS#8 file not created");
                Console.WriteLine("PKCS#8 created: " + pkcs8Path);

                Console.WriteLine("Converting PKCS#8 -> PKCS#1 (roundtrip)...");
                OpenSLLWrapper.ConvertPkcs8ToPkcs1Pem(pkcs8Path, pkcs1Roundtrip);
                if (!File.Exists(pkcs1Roundtrip)) throw new Exception("PKCS#1 roundtrip file not created");
                Console.WriteLine("PKCS#1 roundtrip created: " + pkcs1Roundtrip);

                // Interoperability tests with OpenSSL (if available)
                Console.WriteLine("Checking for openssl in PATH...");
                bool opensslAvailable = false;
                try
                {
                    var psi = new ProcessStartInfo("openssl", "version") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
                    using (var p = Process.Start(psi))
                    {
                        p.WaitForExit(3000);
                        opensslAvailable = p.ExitCode == 0;
                    }
                }
                catch { opensslAvailable = false; }

                if (opensslAvailable)
                {
                    Console.WriteLine("OpenSSL found — running interoperability tests...");

                    string challengeBin = Path.Combine(tmp, "challenge.bin");
                    string sigBin = Path.Combine(tmp, "sig.bin");
                    string opensslSig = Path.Combine(tmp, "openssl_sig.bin");

                    byte[] challengeData = Encoding.UTF8.GetBytes("hello world");
                    File.WriteAllBytes(challengeBin, challengeData);

                    // Verify our signature with openssl
                    File.WriteAllBytes(sigBin, Convert.FromBase64String(signature));
                    var verifyPi = new ProcessStartInfo("openssl", $"dgst -sha256 -verify \"{pubPath}\" -signature \"{sigBin}\" \"{challengeBin}\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
                    using (var p = Process.Start(verifyPi))
                    {
                        string outp = p.StandardOutput.ReadToEnd();
                        string errp = p.StandardError.ReadToEnd();
                        p.WaitForExit(5000);
                        if (!outp.Contains("Verified OK")) throw new Exception($"OpenSSL failed to verify our signature: stdout='{outp}' stderr='{errp}'");
                    }
                    Console.WriteLine("OpenSSL verified signature produced by this library.");

                    // Sign with OpenSSL and verify with our verifier
                    var signPi = new ProcessStartInfo("openssl", $"dgst -sha256 -sign \"{privPath}\" -out \"{opensslSig}\" \"{challengeBin}\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
                    using (var p = Process.Start(signPi))
                    {
                        string outp = p.StandardOutput.ReadToEnd();
                        string errp = p.StandardError.ReadToEnd();
                        p.WaitForExit(5000);
                        if (p.ExitCode != 0) throw new Exception($"OpenSSL signing failed: stdout='{outp}' stderr='{errp}'");
                    }

                    byte[] opensslSigBytes = File.ReadAllBytes(opensslSig);
                    string opensslSigB64 = Convert.ToBase64String(opensslSigBytes);
                    bool ok = OpenSLLWrapper.VerifyBase64Signature(Convert.ToBase64String(challengeData), opensslSigB64, pubPath);
                    if (!ok) throw new Exception("Library failed to verify signature produced by OpenSSL");
                    Console.WriteLine("Library verified signature produced by OpenSSL.");
                }
                else
                {
                    Console.WriteLine("OpenSSL not found in PATH; skipping interoperability tests.");
                }

                Console.WriteLine("All tests passed.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Test failed: " + exMessage(ex));
                return 2;
            }
        }

        static string exMessage(Exception ex)
        {
            var sb = new StringBuilder();
            sb.AppendLine(ex.Message);
            if (ex.InnerException != null) sb.AppendLine(ex.InnerException.Message);
            sb.AppendLine(ex.StackTrace);
            return sb.ToString();
        }
    }
}
