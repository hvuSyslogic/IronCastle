using System;

namespace org.bouncycastle.mail.smime
{
	public class SMIMEException : Exception
	{
		internal Exception e;

		public SMIMEException(string name) : base(name)
		{
		}

		public SMIMEException(string name, Exception e) : base(name)
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