using System;

namespace org.bouncycastle.cmc
{
	public class CMCException : Exception
	{
		private readonly Exception cause;

		public CMCException(string msg) : this(msg, null)
		{
		}

		public CMCException(string msg, Exception cause) : base(msg)
		{
			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}