using System;

namespace org.bouncycastle.dvcs
{
	/// <summary>
	/// DVCS parsing exception - thrown when failed to parse DVCS message.
	/// </summary>
	public class DVCSParsingException : DVCSException
	{
		private const long serialVersionUID = -7895880961377691266L;

		public DVCSParsingException(string message) : base(message)
		{
		}

		public DVCSParsingException(string message, Exception cause) : base(message, cause)
		{
		}
	}

}