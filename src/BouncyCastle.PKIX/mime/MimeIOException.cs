using System;

namespace org.bouncycastle.mime
{

	/// <summary>
	/// General IOException thrown in the mime package and its sub-packages.
	/// </summary>
	public class MimeIOException : IOException
	{
		private Exception cause;

		public MimeIOException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public MimeIOException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}