using System;

namespace org.bouncycastle.cert
{
	public class CertRuntimeException : RuntimeException
	{
		private Exception cause;

		public CertRuntimeException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}
}