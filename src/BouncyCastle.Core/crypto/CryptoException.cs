using System;

namespace org.bouncycastle.crypto
{
	/// <summary>
	/// the foundation class for the hard exceptions thrown by the crypto packages.
	/// </summary>
	public class CryptoException : Exception
	{
		private Exception cause;

		/// <summary>
		/// base constructor.
		/// </summary>
		public CryptoException()
		{
		}

		/// <summary>
		/// create a CryptoException with the given message.
		/// </summary>
		/// <param name="message"> the message to be carried with the exception. </param>
		public CryptoException(string message) : base(message)
		{
		}

		/// <summary>
		/// Create a CryptoException with the given message and underlying cause.
		/// </summary>
		/// <param name="message"> message describing exception. </param>
		/// <param name="cause"> the throwable that was the underlying cause. </param>
		public CryptoException(string message, Exception cause) : base(message)
		{

			this.cause = cause;
		}

		public virtual Exception getCause()
		{
			return cause;
		}
	}

}