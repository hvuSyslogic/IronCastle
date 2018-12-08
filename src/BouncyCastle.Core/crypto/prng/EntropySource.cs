namespace org.bouncycastle.crypto.prng
{
	/// <summary>
	/// Base interface describing an entropy source for a DRBG.
	/// </summary>
	public interface EntropySource
	{
		/// <summary>
		/// Return whether or not this entropy source is regarded as prediction resistant.
		/// </summary>
		/// <returns> true if it is, false otherwise. </returns>
		bool isPredictionResistant();

		/// <summary>
		/// Return a byte array of entropy.
		/// </summary>
		/// <returns>  entropy bytes. </returns>
		byte[] getEntropy();

		/// <summary>
		/// Return the number of bits of entropy this source can produce.
		/// </summary>
		/// <returns> size in bits of the return value of getEntropy. </returns>
		int entropySize();
	}

}