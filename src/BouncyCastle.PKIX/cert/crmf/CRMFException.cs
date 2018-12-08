using System;

namespace org.bouncycastle.cert.crmf
{
	public class CRMFException : Exception
	{
		private Exception cause;

		public CRMFException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}
}