using System;

namespace org.bouncycastle.jce.exception
{

	public class ExtCertPathValidatorException : CertPathValidatorException, ExtException
	{

		private Exception cause;

		public ExtCertPathValidatorException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public ExtCertPathValidatorException(string msg, Exception cause, CertPath certPath, int index) : base(msg, cause, certPath, index)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}