using System;

namespace org.bouncycastle.dvcs
{
	/// <summary>
	/// General DVCSException.
	/// </summary>
	public class DVCSException : Exception
	{
		private const long serialVersionUID = 389345256020131488L;

		private Exception cause;

		public DVCSException(string message) : base(message)
		{
		}

		public DVCSException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}