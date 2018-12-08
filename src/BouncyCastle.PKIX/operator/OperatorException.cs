using System;

namespace org.bouncycastle.@operator
{
	public class OperatorException : Exception
	{
		private Exception cause;

		public OperatorException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public OperatorException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}