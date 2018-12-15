using System;
using System.IO;

namespace org.bouncycastle.Port.java.lang
{
    public class IllegalArgumentException : ArgumentException
    {
        public IllegalArgumentException() 
        {

        }

        public IllegalArgumentException(string message) :base(message)
        {
            
        }

        public IllegalArgumentException(string eMessage, Exception ioException)
        {
            throw new NotImplementedException();
        }
    }
}
