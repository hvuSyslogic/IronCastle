using System;
using System.IO;

namespace org.bouncycastle.crypto.tls
{

	public class TlsException : IOException
	{
		// TODO Some day we might be able to just pass this down to IOException (1.6+)
		protected internal Exception cause;

		public TlsException(string message, Exception cause) : base(message)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}