using System;

namespace org.bouncycastle.openssl
{

	public class PEMException : IOException
	{
		internal Exception underlying;

		public PEMException(string message) : base(message)
		{
		}

		public PEMException(string message, Exception underlying) : base(message)
		{
			this.underlying = underlying;
		}

		public virtual Exception getUnderlyingException()
		{
			return underlying;
		}


		public virtual Exception getCause()
		{
			return underlying;
		}
	}

}