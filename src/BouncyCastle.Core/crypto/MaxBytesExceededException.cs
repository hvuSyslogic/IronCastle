namespace org.bouncycastle.crypto
{
	/// <summary>
	/// this exception is thrown whenever a cipher requires a change of key, iv
	/// or similar after x amount of bytes enciphered
	/// </summary>
	public class MaxBytesExceededException : RuntimeCryptoException
	{
		/// <summary>
		/// base constructor.
		/// </summary>
		public MaxBytesExceededException()
		{
		}

		/// <summary>
		/// create an with the given message.
		/// </summary>
		/// <param name="message"> the message to be carried with the exception. </param>
		public MaxBytesExceededException(string message) : base(message)
		{
		}
	}

}