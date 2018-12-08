using System;

namespace org.bouncycastle.jcajce.provider.util
{

	public class BadBlockException : BadPaddingException
	{
		private readonly Exception cause;

		public BadBlockException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}