using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util.encoders
{
	/// <summary>
	/// Exception thrown if an attempt is made to decode invalid data, or some other failure occurs.
	/// </summary>
	public class DecoderException : IllegalStateException
	{
		private Exception cause;

		public DecoderException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}