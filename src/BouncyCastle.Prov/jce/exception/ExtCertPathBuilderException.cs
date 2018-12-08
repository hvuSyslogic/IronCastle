using System;

namespace org.bouncycastle.jce.exception
{

	public class ExtCertPathBuilderException : CertPathBuilderException, ExtException
	{
		private Exception cause;

		public ExtCertPathBuilderException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public ExtCertPathBuilderException(string msg, Exception cause, CertPath certPath, int index) : base(msg, cause)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}