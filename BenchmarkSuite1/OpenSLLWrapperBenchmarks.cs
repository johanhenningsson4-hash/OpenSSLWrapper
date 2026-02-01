using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using OSS = global::OpenSLLWrapper.OpenSLLWrapper;

namespace OpenSLLWrapper.Benchmarks
{
    [MemoryDiagnoser]
    public class OpenSLLWrapperBenchmarks
    {
        private byte[] _data;
        private byte[] _privKey;

        [GlobalSetup]
        public void Setup()
        {
            _data = Encoding.UTF8.GetBytes("benchmark-challenge-data");
            // Generate a key once for signing benchmarks
            _privKey = OSS.GenerateRsaPrivateKeyBytes(2048);
        }

        [Benchmark(Description = "Generate RSA 2048")]
        public byte[] GenerateRsaKey_2048()
        {
            return OSS.GenerateRsaPrivateKeyBytes(2048);
        }

        [Benchmark(Description = "Sign PKCS#1 SHA256")]
        public string Sign_Pkcs1()
        {
            return OSS.SignChallengeData(_data, _privKey, usePss: false);
        }

        [Benchmark(Description = "Sign RSASSA-PSS SHA256")]
        public string Sign_Pss()
        {
            return OSS.SignChallengeData(_data, _privKey, usePss: true);
        }
    }
}
