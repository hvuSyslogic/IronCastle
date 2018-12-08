using System;

namespace org.bouncycastle.cert.dane
{
	/// <summary>
	/// General checked Exception thrown in the DANE package.
	/// </summary>
	public class DANEException : Exception
	{
		private Exception cause;

		public DANEException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public DANEException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}