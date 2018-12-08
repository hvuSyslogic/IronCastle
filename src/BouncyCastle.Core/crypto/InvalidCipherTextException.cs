using System;

namespace org.bouncycastle.crypto
{
	/// <summary>
	/// this exception is thrown whenever we find something we don't expect in a
	/// message.
	/// </summary>
	public class InvalidCipherTextException : CryptoException
	{
		/// <summary>
		/// base constructor.
		/// </summary>
		public InvalidCipherTextException()
		{
		}

		/// <summary>
		/// create a InvalidCipherTextException with the given message.
		/// </summary>
		/// <param name="message"> the message to be carried with the exception. </param>
		public InvalidCipherTextException(string message) : base(message)
		{
		}

		/// <summary>
		/// create a InvalidCipherTextException with the given message.
		/// </summary>
		/// <param name="message"> the message to be carried with the exception. </param>
		/// <param name="cause"> the root cause of the exception. </param>
		public InvalidCipherTextException(string message, Exception cause) : base(message, cause)
		{
		}
	}

}