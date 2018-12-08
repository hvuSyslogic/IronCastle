using System;
using System.IO;

namespace org.bouncycastle.util.io.pem
{

	/// <summary>
	/// Exception thrown on failure to generate a PEM object.
	/// </summary>
	public class PemGenerationException : IOException
	{
		private Exception cause;

		public PemGenerationException(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		public PemGenerationException(string message) : base(message)
		{
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}