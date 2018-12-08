using System;

namespace org.bouncycastle.openpgp
{
	public class PGPRuntimeOperationException : RuntimeException
	{
		private readonly Exception cause;

		public PGPRuntimeOperationException(string message, Exception cause) : base(message)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}