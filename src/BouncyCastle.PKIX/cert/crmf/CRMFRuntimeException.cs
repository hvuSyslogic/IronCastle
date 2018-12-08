using System;

namespace org.bouncycastle.cert.crmf
{
	public class CRMFRuntimeException : RuntimeException
	{
		private Exception cause;

		public CRMFRuntimeException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}
}