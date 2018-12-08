using System;

namespace org.bouncycastle.cms
{
	public class CMSException : Exception
	{
		internal Exception e;

		public CMSException(string msg) : base(msg)
		{
		}

		public CMSException(string msg, Exception e) : base(msg)
		{

			this.e = e;
		}

		public virtual Exception getUnderlyingException()
		{
			return e;
		}

		public virtual Exception getCause()
		{
			return e;
		}
	}

}