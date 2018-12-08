using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// The base class for parameters to key generators.
	/// </summary>
	public class KeyGenerationParameters
	{
		private SecureRandom random;
		private int strength;

		/// <summary>
		/// initialise the generator with a source of randomness
		/// and a strength (in bits).
		/// </summary>
		/// <param name="random"> the random byte source. </param>
		/// <param name="strength"> the size, in bits, of the keys we want to produce. </param>
		public KeyGenerationParameters(SecureRandom random, int strength)
		{
			this.random = random;
			this.strength = strength;
		}

		/// <summary>
		/// return the random source associated with this
		/// generator.
		/// </summary>
		/// <returns> the generators random source. </returns>
		public virtual SecureRandom getRandom()
		{
			return random;
		}

		/// <summary>
		/// return the bit strength for keys produced by this generator,
		/// </summary>
		/// <returns> the strength of the keys this generator produces (in bits). </returns>
		public virtual int getStrength()
		{
			return strength;
		}
	}

}