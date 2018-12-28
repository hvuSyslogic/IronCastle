using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.prng
{

	public class X931SecureRandom : SecureRandom
	{
		private readonly bool predictionResistant;
		private readonly SecureRandom randomSource;
		private readonly X931RNG drbg;

		public X931SecureRandom(SecureRandom randomSource, X931RNG drbg, bool predictionResistant)
		{
			this.randomSource = randomSource;
			this.drbg = drbg;
			this.predictionResistant = predictionResistant;
		}

		public override void setSeed(byte[] seed)
		{
			lock (this)
			{
				if (randomSource != null)
				{
					this.randomSource.setSeed(seed);
				}
			}
		}

		public override void setSeed(long seed)
		{
			lock (this)
			{
				// this will happen when SecureRandom() is created
				if (randomSource != null)
				{
					this.randomSource.setSeed(seed);
				}
			}
		}

		public override void nextBytes(byte[] bytes)
		{
			lock (this)
			{
				// check if a reseed is required...
				if (drbg.generate(bytes, predictionResistant) < 0)
				{
					drbg.reseed();
					drbg.generate(bytes, predictionResistant);
				}
			}
		}

		public override byte[] generateSeed(int numBytes)
		{
			return EntropyUtil.generateSeed(drbg.getEntropySource(), numBytes);
		}
	}

}