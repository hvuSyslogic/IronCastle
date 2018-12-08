using System;
using System.IO;

namespace org.bouncycastle.crypto.io
{

	/// <summary>
	/// <seealso cref="IOException"/> wrapper around an exception indicating a problem with the use of a cipher.
	/// </summary>
	public class CipherIOException : IOException
	{
		private const long serialVersionUID = 1L;

		private readonly Exception cause;

		public CipherIOException(string message, Exception cause) : base(message)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}
}