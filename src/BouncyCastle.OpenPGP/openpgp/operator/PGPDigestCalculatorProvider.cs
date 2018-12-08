namespace org.bouncycastle.openpgp.@operator
{
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;

	/// <summary>
	/// A factory for digest algorithms.
	/// </summary>
	public interface PGPDigestCalculatorProvider
	{
		/// <summary>
		/// Construct a new instance of a cryptographic digest.
		/// </summary>
		/// <param name="algorithm"> the identifier of the <seealso cref="HashAlgorithmTags digest algorithm"/> to
		///            instantiate. </param>
		/// <returns> a digest calculator for the specified algorithm. </returns>
		/// <exception cref="PGPException"> if an error occurs constructing the specified digest. </exception>
		PGPDigestCalculator get(int algorithm);
	}

}