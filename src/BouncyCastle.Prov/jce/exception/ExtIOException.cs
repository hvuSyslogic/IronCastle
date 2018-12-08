using System;

namespace org.bouncycastle.jce.exception
{

	public class ExtIOException : IOException, ExtException
	{
		private Exception cause;

		public ExtIOException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}