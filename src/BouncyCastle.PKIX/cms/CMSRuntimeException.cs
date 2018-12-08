using System;

namespace org.bouncycastle.cms
{
	public class CMSRuntimeException : RuntimeException
	{
		internal Exception e;

		public CMSRuntimeException(string name) : base(name)
		{
		}

		public CMSRuntimeException(string name, Exception e) : base(name)
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