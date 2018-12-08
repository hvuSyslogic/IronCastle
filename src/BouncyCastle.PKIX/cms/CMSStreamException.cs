using System;

namespace org.bouncycastle.cms
{

	public class CMSStreamException : IOException
	{
		private readonly Exception underlying;

		public CMSStreamException(string msg) : base(msg)
		{
			this.underlying = null;
		}

		public CMSStreamException(string msg, Exception underlying) : base(msg)
		{
			this.underlying = underlying;
		}

		public virtual Exception getCause()
		{
			return underlying;
		}
	}

}