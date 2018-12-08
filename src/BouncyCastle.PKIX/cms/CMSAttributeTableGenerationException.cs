using System;

namespace org.bouncycastle.cms
{
	public class CMSAttributeTableGenerationException : CMSRuntimeException
	{
		internal new Exception e;

		public CMSAttributeTableGenerationException(string name) : base(name)
		{
		}

		public CMSAttributeTableGenerationException(string name, Exception e) : base(name)
		{

			this.e = e;
		}

		public override Exception getUnderlyingException()
		{
			return e;
		}

		public override Exception getCause()
		{
			return e;
		}
	}

}