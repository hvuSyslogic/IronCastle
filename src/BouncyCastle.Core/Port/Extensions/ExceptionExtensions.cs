using System;

namespace org.bouncycastle.Port.Extensions
{
    public static class ExceptionExtensions
    {
        public static string printStackTrace(this Exception e)
        {
            return e.StackTrace;
        }

        public static string getMessage(this Exception e)
        {
            return e.Message;
        }
    }
}
