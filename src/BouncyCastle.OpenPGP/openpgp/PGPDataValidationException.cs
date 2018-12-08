namespace org.bouncycastle.openpgp
{
	/// <summary>
	/// Thrown if the iv at the start of a data stream indicates the wrong key
	/// is being used.
	/// </summary>
	public class PGPDataValidationException : PGPException
	{
		/// <param name="message"> </param>
		public PGPDataValidationException(string message) : base(message)
		{
		}
	}

}