namespace org.bouncycastle.crypto
{
	/// <summary>
	/// Interface for a converter that produces a byte encoding for a char array.
	/// </summary>
	public interface CharToByteConverter
	{
		/// <summary>
		/// Return the type of the conversion.
		/// </summary>
		/// <returns> a type name for the conversion. </returns>
		string getType();

		/// <summary>
		/// Return a byte encoded representation of the passed in password.
		/// </summary>
		/// <param name="password"> the characters to encode. </param>
		/// <returns> a byte encoding of password. </returns>
		byte[] convert(char[] password);
	}

}