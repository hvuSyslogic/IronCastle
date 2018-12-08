using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	public class ExtendedInvalidKeySpecException : InvalidKeySpecException
	{
		private Exception cause;

		public ExtendedInvalidKeySpecException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}