using System;

namespace org.bouncycastle.openpgp
{
	/// <summary>
	/// generic exception class for PGP encoding/decoding problems
	/// </summary>
	public class PGPException : Exception
	{
		internal Exception underlying;

		public PGPException(string message) : base(message)
		{
		}

		public PGPException(string message, Exception underlying) : base(message)
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