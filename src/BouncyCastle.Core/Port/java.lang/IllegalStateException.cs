using System;

namespace org.bouncycastle.Port
{
    public class IllegalStateException : Exception
    {
        public IllegalStateException()
        {

        }

        public IllegalStateException(string message) :base(message)
        {
            
        }

        public IllegalStateException(Exception ex) : base(string.Empty, ex)
        {

        }

        public IllegalStateException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
