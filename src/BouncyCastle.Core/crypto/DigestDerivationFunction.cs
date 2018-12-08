namespace org.bouncycastle.crypto
{
	/// <summary>
	/// base interface for general purpose Digest based byte derivation functions.
	/// </summary>
	public interface DigestDerivationFunction : DerivationFunction
	{
		/// <summary>
		/// return the message digest used as the basis for the function
		/// </summary>
		Digest getDigest();
	}

}