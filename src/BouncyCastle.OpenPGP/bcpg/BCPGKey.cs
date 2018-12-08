namespace org.bouncycastle.bcpg
{
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// base interface for a PGP key
	/// </summary>
	public interface BCPGKey : Encodable
	{
		/// <summary>
		/// Return the base format for this key - in the case of the symmetric keys it will generally
		/// be raw indicating that the key is just a straight byte representation, for an asymmetric
		/// key the format will be PGP, indicating the key is a string of MPIs encoded in PGP format.
		/// </summary>
		/// <returns> "RAW" or "PGP" </returns>
		string getFormat();

		/// <summary>
		/// return a string of bytes giving the encoded format of the key, as described by it's format.
		/// </summary>
		/// <returns> byte[] </returns>
		byte[] getEncoded();

	}

}