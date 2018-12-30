using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.prng
{

	/// <summary>
	/// An EntropySourceProvider where entropy generation is based on a SecureRandom output using SecureRandom.generateSeed().
	/// </summary>
	public class BasicEntropySourceProvider : EntropySourceProvider
	{
		private readonly SecureRandom _sr;
		private readonly bool _predictionResistant;

		/// <summary>
		/// Create a entropy source provider based on the passed in SecureRandom.
		/// </summary>
		/// <param name="random"> the SecureRandom to base EntropySource construction on. </param>
		/// <param name="isPredictionResistant"> boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is). </param>
		public BasicEntropySourceProvider(SecureRandom random, bool isPredictionResistant)
		{
			_sr = random;
			_predictionResistant = isPredictionResistant;
		}

		/// <summary>
		/// Return an entropy source that will create bitsRequired bits of entropy on
		/// each invocation of getEntropy().
		/// </summary>
		/// <param name="bitsRequired"> size (in bits) of entropy to be created by the provided source. </param>
		/// <returns> an EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method. </returns>

		public virtual EntropySource get(int bitsRequired)
		{
			return new EntropySourceAnonymousInnerClass(this, bitsRequired);
		}

		public class EntropySourceAnonymousInnerClass : EntropySource
		{
			private readonly BasicEntropySourceProvider outerInstance;

			private int bitsRequired;

			public EntropySourceAnonymousInnerClass(BasicEntropySourceProvider outerInstance, int bitsRequired)
			{
				this.outerInstance = outerInstance;
				this.bitsRequired = bitsRequired;
			}

			public bool isPredictionResistant()
			{
				return outerInstance._predictionResistant;
			}

			public byte[] getEntropy()
			{
				// is the RNG regarded as useful for seeding?
				if (outerInstance._sr is SP800SecureRandom || outerInstance._sr is X931SecureRandom)
				{
					byte[] rv = new byte[(bitsRequired + 7) / 8];

					outerInstance._sr.nextBytes(rv);

					return rv;
				}
				return outerInstance._sr.generateSeed((bitsRequired + 7) / 8);
			}

			public int entropySize()
			{
				return bitsRequired;
			}
		}
	}

}