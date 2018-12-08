using System;

namespace org.bouncycastle.pkcs
{
	/// <summary>
	/// General checked Exception thrown in the cert package and its sub-packages.
	/// </summary>
	public class PKCSException : Exception
	{
		private Exception cause;

		public PKCSException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public PKCSException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}