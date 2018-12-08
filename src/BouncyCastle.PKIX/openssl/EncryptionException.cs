using System;

namespace org.bouncycastle.openssl
{
	public class EncryptionException : PEMException
	{
		private Exception cause;

		public EncryptionException(string msg) : base(msg)
		{
		}

		public EncryptionException(string msg, Exception ex) : base(msg)
		{
			this.cause = ex;
		}

		public override Exception getCause()
		{
			return cause;
		}
	}
}