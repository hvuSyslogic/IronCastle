using System;

namespace org.bouncycastle.x509
{
	public class NoSuchParserException : Exception
	{
		public NoSuchParserException(string message) : base(message)
		{
		}
	}

}