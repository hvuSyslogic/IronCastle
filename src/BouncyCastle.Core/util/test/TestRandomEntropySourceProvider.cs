using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.prng;

namespace org.bouncycastle.util.test
{

		
	/// <summary>
	/// A class for returning "quick entropy" for testing purposes.
	/// </summary>
	public class TestRandomEntropySourceProvider : EntropySourceProvider
	{
		private readonly SecureRandom _sr;
		private readonly bool _predictionResistant;

		/// <summary>
		/// Create a test entropy source provider.
		/// </summary>
		/// <param name="isPredictionResistant"> boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is). </param>
		public TestRandomEntropySourceProvider(bool isPredictionResistant)
		{
			_sr = new SecureRandom();
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
			private readonly TestRandomEntropySourceProvider outerInstance;

			private int bitsRequired;

			public EntropySourceAnonymousInnerClass(TestRandomEntropySourceProvider outerInstance, int bitsRequired)
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
				byte[] rv = new byte[(bitsRequired + 7) / 8];
				outerInstance._sr.nextBytes(rv);
				return rv;
			}

			public int entropySize()
			{
				return bitsRequired;
			}
		}
	}

}