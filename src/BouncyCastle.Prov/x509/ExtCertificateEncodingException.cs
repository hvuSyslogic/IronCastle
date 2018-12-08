using System;

namespace org.bouncycastle.x509
{

	public class ExtCertificateEncodingException : CertificateEncodingException
	{
		internal Exception cause;

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