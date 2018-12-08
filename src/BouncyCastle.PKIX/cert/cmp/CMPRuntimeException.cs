using System;

namespace org.bouncycastle.cert.cmp
{
	public class CMPRuntimeException : RuntimeException
	{
		private Exception cause;

		public CMPRuntimeException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}
}