﻿using System;

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

        public IllegalStateException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
