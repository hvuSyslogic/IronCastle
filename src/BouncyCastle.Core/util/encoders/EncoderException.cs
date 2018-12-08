using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util.encoders
{
	/// <summary>
	/// Exception thrown if an attempt is made to encode invalid data, or some other failure occurs.
	/// </summary>
	public class EncoderException : IllegalStateException
	{
		private Exception cause;

		public EncoderException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}