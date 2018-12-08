using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.x509
{

	public class ExtCRLException : CRLException
	{
		internal Exception cause;

		public ExtCRLException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}