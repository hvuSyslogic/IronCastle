using System;

namespace org.bouncycastle.cert.cmp
{
	public class CMPException : Exception
	{
		private Exception cause;

		public CMPException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public CMPException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}
}