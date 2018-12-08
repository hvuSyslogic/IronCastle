using System;

namespace org.bouncycastle.eac
{

	/// <summary>
	/// General IOException thrown in the cert package and its sub-packages.
	/// </summary>
	public class EACIOException : IOException
	{
		private Exception cause;

		public EACIOException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public EACIOException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}