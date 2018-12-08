using System;

namespace org.bouncycastle.@operator
{

	public class OperatorStreamException : IOException
	{
		private Exception cause;

		public OperatorStreamException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}