using System;

namespace org.bouncycastle.x509
{
	public class NoSuchStoreException : Exception
	{
		public NoSuchStoreException(string message) : base(message)
		{
		}
	}

}