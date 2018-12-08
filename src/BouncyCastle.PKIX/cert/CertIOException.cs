using System;

namespace org.bouncycastle.cert
{

	/// <summary>
	/// General IOException thrown in the cert package and its sub-packages.
	/// </summary>
	public class CertIOException : IOException
	{
		private Exception cause;

		public CertIOException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public CertIOException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}