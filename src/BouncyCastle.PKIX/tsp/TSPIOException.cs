using System;

namespace org.bouncycastle.tsp
{

	public class TSPIOException : IOException
	{
		internal Exception underlyingException;

		public TSPIOException(string message) : base(message)
		{
		}

		public TSPIOException(string message, Exception e) : base(message)
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