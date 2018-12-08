namespace org.bouncycastle.@operator
{
	/// <summary>
	/// Interface for ContentVerifiers that also support raw signatures that can be
	/// verified using the digest of the calculated data.
	/// </summary>
	public interface RawContentVerifier
	{
		/// <summary>
		/// Verify that the expected signature value was derived from the passed in digest.
		/// </summary>
		/// <param name="digest"> digest calculated from the content. </param>
		/// <param name="expected"> expected value of the signature </param>
		/// <returns> true if the expected signature is derived from the digest, false otherwise. </returns>
		bool verify(byte[] digest, byte[] expected);
	}

}