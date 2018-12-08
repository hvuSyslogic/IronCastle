namespace org.bouncycastle.crypto.prng.drbg
{
	/// <summary>
	/// Interface to SP800-90A deterministic random bit generators.
	/// </summary>
	public interface SP80090DRBG
	{
		/// <summary>
		/// Return the block size of the DRBG.
		/// </summary>
		/// <returns> the block size (in bits) produced by each round of the DRBG. </returns>
		int getBlockSize();

		/// <summary>
		/// Populate a passed in array with random data.
		/// </summary>
		/// <param name="output"> output array for generated bits. </param>
		/// <param name="additionalInput"> additional input to be added to the DRBG in this step. </param>
		/// <param name="predictionResistant"> true if a reseed should be forced, false otherwise.
		/// </param>
		/// <returns> number of bits generated, -1 if a reseed required. </returns>
		int generate(byte[] output, byte[] additionalInput, bool predictionResistant);

		/// <summary>
		/// Reseed the DRBG.
		/// </summary>
		/// <param name="additionalInput"> additional input to be added to the DRBG in this step. </param>
		void reseed(byte[] additionalInput);
	}

}