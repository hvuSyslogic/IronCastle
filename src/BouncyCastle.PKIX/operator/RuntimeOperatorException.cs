using System;

namespace org.bouncycastle.@operator
{
	public class RuntimeOperatorException : RuntimeException
	{
		private Exception cause;

		public RuntimeOperatorException(string msg) : base(msg)
		{
		}

		public RuntimeOperatorException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}