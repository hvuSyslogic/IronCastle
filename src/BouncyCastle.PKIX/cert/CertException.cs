using System;

namespace org.bouncycastle.cert
{
	/// <summary>
	/// General checked Exception thrown in the cert package and its sub-packages.
	/// </summary>
	public class CertException : Exception
	{
		private Exception cause;

		public CertException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public CertException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}