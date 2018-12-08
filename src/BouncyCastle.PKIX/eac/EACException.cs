using System;

namespace org.bouncycastle.eac
{
	/// <summary>
	/// General checked Exception thrown in the cert package and its sub-packages.
	/// </summary>
	public class EACException : Exception
	{
		private Exception cause;

		public EACException(string msg, Exception cause) : base(msg)
		{

			this.cause = cause;
		}

		public EACException(string msg) : base(msg)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}