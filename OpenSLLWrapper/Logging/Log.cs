using System;
using System.IO;

namespace OpenSLLWrapper.Logging
{
    /// <summary>
    /// Simple static logger used across the library and tests.
    /// Default writes to Console.Out; callers may set a different TextWriter.
    /// </summary>
    public static class Log
    {
        private static TextWriter writer = Console.Out;
        private static readonly object sync = new object();

        public static void SetOutput(TextWriter textWriter)
        {
            if (textWriter == null) throw new ArgumentNullException(nameof(textWriter));
            lock (sync) { writer = textWriter; }
        }

        public static void Info(string message)
        {
            lock (sync) writer.WriteLine($"[INFO] [{DateTime.UtcNow:O}] {message}");
        }

        public static void Warn(string message)
        {
            lock (sync) writer.WriteLine($"[WARN] [{DateTime.UtcNow:O}] {message}");
        }

        public static void Error(string message)
        {
            lock (sync) writer.WriteLine($"[ERROR] [{DateTime.UtcNow:O}] {message}");
        }

        public static void Error(Exception ex)
        {
            lock (sync) writer.WriteLine($"[ERROR] [{DateTime.UtcNow:O}] {ex}");
        }
    }
}
