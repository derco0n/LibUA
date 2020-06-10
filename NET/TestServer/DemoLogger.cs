using System;
using LibUA;

namespace TestServer
{
    /// <summary>
    /// This is a simple logger
    /// </summary>
    class DemoLogger : ILogger
    {
        public bool HasLevel(LogLevel Level)
        {
            return true;
        }

        public void LevelSet(LogLevel Mask)
        {
        }

        public void Log(LogLevel Level, string Str)
        {
            Console.WriteLine("[{0}] {1}", Level.ToString(), Str);
        }
    }
}
