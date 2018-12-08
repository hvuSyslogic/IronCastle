using System;

namespace org.bouncycastle.Port
{
    public class RuntimeException : Exception
    {
        public RuntimeException(string message) :base(message)
        {
            
        }

        public RuntimeException()
        {
            throw new NotImplementedException();
        }

        public RuntimeException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
