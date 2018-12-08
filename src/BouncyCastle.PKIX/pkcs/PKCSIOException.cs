using System;

namespace org.bouncycastle.pkcs
{

	/// <summary>
	/// General IOException thrown in the cert package and its sub-packages.
	/// </summary>
	public class PKCSIOException : IOException
	{
		private Exception cause;

		public PKCSIOException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public PKCSIOException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}