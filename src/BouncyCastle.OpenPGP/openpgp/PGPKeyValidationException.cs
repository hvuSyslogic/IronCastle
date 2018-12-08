namespace org.bouncycastle.openpgp
{
	/// <summary>
	/// Thrown if the key checksum is invalid.
	/// </summary>
	public class PGPKeyValidationException : PGPException
	{
		/// <param name="message"> </param>
		public PGPKeyValidationException(string message) : base(message)
		{
		}
	}

}