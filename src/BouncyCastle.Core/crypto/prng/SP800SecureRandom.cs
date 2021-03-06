﻿using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.prng.drbg;

namespace org.bouncycastle.crypto.prng
{

	
	public class SP800SecureRandom : SecureRandom
	{
		private readonly DRBGProvider drbgProvider;
		private readonly bool predictionResistant;
		private readonly SecureRandom randomSource;
		private readonly EntropySource entropySource;

		private SP80090DRBG drbg;

		public SP800SecureRandom(SecureRandom randomSource, EntropySource entropySource, DRBGProvider drbgProvider, bool predictionResistant)
		{
			this.randomSource = randomSource;
			this.entropySource = entropySource;
			this.drbgProvider = drbgProvider;
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
				if (drbg == null)
				{
					drbg = drbgProvider.get(entropySource);
				}

				// check if a reseed is required...
				if (drbg.generate(bytes, null, predictionResistant) < 0)
				{
					drbg.reseed(null);
					drbg.generate(bytes, null, predictionResistant);
				}
			}
		}

		public override byte[] generateSeed(int numBytes)
		{
			return EntropyUtil.generateSeed(entropySource, numBytes);
		}

		/// <summary>
		/// Force a reseed of the DRBG
		/// </summary>
		/// <param name="additionalInput"> optional additional input </param>
		public virtual void reseed(byte[] additionalInput)
		{
			lock (this)
			{
				if (drbg == null)
				{
					drbg = drbgProvider.get(entropySource);
				}

				drbg.reseed(additionalInput);
			}
		}
	}

}