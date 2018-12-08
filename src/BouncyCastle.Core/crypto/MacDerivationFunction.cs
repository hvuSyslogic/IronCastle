namespace org.bouncycastle.crypto
{
	/// <summary>
	/// base interface for general purpose Mac based byte derivation functions.
	/// </summary>
	public interface MacDerivationFunction : DerivationFunction
	{
		/// <summary>
		/// return the MAC used as the basis for the function
		/// </summary>
		/// <returns> the Mac. </returns>
		Mac getMac();
	}

}