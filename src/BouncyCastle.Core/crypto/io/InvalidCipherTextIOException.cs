using System;
using System.IO;

namespace org.bouncycastle.crypto.io
{

	/// <summary>
	/// <seealso cref="IOException"/> wrapper around an exception indicating an invalid ciphertext, such as in
	/// authentication failure during finalisation of an AEAD cipher. For use in streams that need to
	/// expose invalid ciphertext errors.
	/// </summary>
	public class InvalidCipherTextIOException : CipherIOException
	{
		private const long serialVersionUID = 1L;

		public InvalidCipherTextIOException(string message, Exception cause) : base(message, cause)
		{
		}
	}
}