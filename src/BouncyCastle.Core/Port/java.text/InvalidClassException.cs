using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastle.Core.Port.java.text
{
    public class InvalidClassException : Exception
    {
        public InvalidClassException(string message, string name) : base(message)
        {

        }
    }
}
