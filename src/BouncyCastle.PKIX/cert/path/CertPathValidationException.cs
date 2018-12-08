using System;

namespace org.bouncycastle.cert.path
{
	public class CertPathValidationException : Exception
	{
		private readonly Exception cause;

		public CertPathValidationException(string msg) : this(msg, null)
		{
		}

		public CertPathValidationException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}