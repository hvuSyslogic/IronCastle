using System;

namespace org.bouncycastle.tsp
{
	public class TSPException : Exception
	{
		internal Exception underlyingException;

		public TSPException(string message) : base(message)
		{
		}

		public TSPException(string message, Exception e) : base(message)
		{
			underlyingException = e;
		}

		public virtual Exception getUnderlyingException()
		{
			return (Exception)underlyingException;
		}

		public virtual Exception getCause()
		{
			return underlyingException;
		}
	}

}