using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.prng
{

	public class X931RNG
	{
		private static readonly long BLOCK64_RESEED_MAX = 1L << (16 - 1);
		private static readonly long BLOCK128_RESEED_MAX = 1L << (24 - 1);
		private static readonly int BLOCK64_MAX_BITS_REQUEST = 1 << (13 - 1);
		private static readonly int BLOCK128_MAX_BITS_REQUEST = 1 << (19 - 1);

		private readonly BlockCipher engine;
		private readonly EntropySource entropySource;

		private readonly byte[] DT;
		private readonly byte[] I;
		private readonly byte[] R;

		private byte[] V;

		private long reseedCounter = 1;

		/// 
		/// <param name="engine"> </param>
		/// <param name="entropySource"> </param>
		public X931RNG(BlockCipher engine, byte[] dateTimeVector, EntropySource entropySource)
		{
			this.engine = engine;
			this.entropySource = entropySource;

			this.DT = new byte[engine.getBlockSize()];

			JavaSystem.arraycopy(dateTimeVector, 0, DT, 0, DT.Length);

			this.I = new byte[engine.getBlockSize()];
			this.R = new byte[engine.getBlockSize()];
		}

		/// <summary>
		/// Populate a passed in array with random data.
		/// </summary>
		/// <param name="output"> output array for generated bits. </param>
		/// <param name="predictionResistant"> true if a reseed should be forced, false otherwise.
		/// </param>
		/// <returns> number of bits generated, -1 if a reseed required. </returns>
		public virtual int generate(byte[] output, bool predictionResistant)
		{
			if (R.Length == 8) // 64 bit block size
			{
				if (reseedCounter > BLOCK64_RESEED_MAX)
				{
					return -1;
				}

				if (isTooLarge(output, BLOCK64_MAX_BITS_REQUEST / 8))
				{
					throw new IllegalArgumentException("Number of bits per request limited to " + BLOCK64_MAX_BITS_REQUEST);
				}
			}
			else
			{
				if (reseedCounter > BLOCK128_RESEED_MAX)
				{
					return -1;
				}

				if (isTooLarge(output, BLOCK128_MAX_BITS_REQUEST / 8))
				{
					throw new IllegalArgumentException("Number of bits per request limited to " + BLOCK128_MAX_BITS_REQUEST);
				}
			}

			if (predictionResistant || V == null)
			{
				V = entropySource.getEntropy();
				if (V.Length != engine.getBlockSize())
				{
					throw new IllegalStateException("Insufficient entropy returned");
				}
			}

			int m = output.Length / R.Length;

			for (int i = 0; i < m; i++)
			{
				engine.processBlock(DT, 0, I, 0);
				process(R, I, V);
				process(V, R, I);

				JavaSystem.arraycopy(R, 0, output, i * R.Length, R.Length);

				increment(DT);
			}

			int bytesToCopy = (output.Length - m * R.Length);

			if (bytesToCopy > 0)
			{
				engine.processBlock(DT, 0, I, 0);
				process(R, I, V);
				process(V, R, I);

				JavaSystem.arraycopy(R, 0, output, m * R.Length, bytesToCopy);

				increment(DT);
			}

			reseedCounter++;

			return output.Length;
		}

		/// <summary>
		/// Reseed the RNG.
		/// </summary>
		public virtual void reseed()
		{
			V = entropySource.getEntropy();
			if (V.Length != engine.getBlockSize())
			{
				throw new IllegalStateException("Insufficient entropy returned");
			}
			reseedCounter = 1;
		}

		public virtual EntropySource getEntropySource()
		{
			return entropySource;
		}

		private void process(byte[] res, byte[] a, byte[] b)
		{
			for (int i = 0; i != res.Length; i++)
			{
				res[i] = (byte)(a[i] ^ b[i]);
			}

			engine.processBlock(res, 0, res, 0);
		}

		private void increment(byte[] val)
		{
			for (int i = val.Length - 1; i >= 0; i--)
			{
				if (++val[i] != 0)
				{
					break;
				}
			}
		}

		private static bool isTooLarge(byte[] bytes, int maxBytes)
		{
			return bytes != null && bytes.Length > maxBytes;
		}
	}

}