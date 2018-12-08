using System;

namespace org.bouncycastle.jce.exception
{

	public class ExtCertificateEncodingException : CertificateEncodingException, ExtException
	{
		private Exception cause;

		public ExtCertificateEncodingException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}