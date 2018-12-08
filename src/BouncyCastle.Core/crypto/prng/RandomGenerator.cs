namespace org.bouncycastle.crypto.prng
{
	/// <summary>
	/// Generic interface for objects generating random bytes.
	/// </summary>
	public interface RandomGenerator
	{
		/// <summary>
		/// Add more seed material to the generator.
		/// </summary>
		/// <param name="seed"> a byte array to be mixed into the generator's state. </param>
		void addSeedMaterial(byte[] seed);

		/// <summary>
		/// Add more seed material to the generator.
		/// </summary>
		/// <param name="seed"> a long value to be mixed into the generator's state. </param>
		void addSeedMaterial(long seed);

		/// <summary>
		/// Fill bytes with random values.
		/// </summary>
		/// <param name="bytes"> byte array to be filled. </param>
		void nextBytes(byte[] bytes);

		/// <summary>
		/// Fill part of bytes with random values.
		/// </summary>
		/// <param name="bytes"> byte array to be filled. </param>
		/// <param name="start"> index to start filling at. </param>
		/// <param name="len"> length of segment to fill. </param>
		void nextBytes(byte[] bytes, int start, int len);

	}

}