using System;

namespace org.bouncycastle.cert.ocsp
{
	public class OCSPException : Exception
	{
		private Exception cause;

		public OCSPException(string name) : base(name)
		{
		}

		public OCSPException(string name, Exception cause) : base(name)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}