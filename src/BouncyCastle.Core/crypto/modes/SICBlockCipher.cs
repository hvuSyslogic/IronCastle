using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.modes
{
			
	/// <summary>
	/// Implements the Segmented Integer Counter (SIC) mode on top of a simple
	/// block cipher. This mode is also known as CTR mode.
	/// </summary>
	public class SICBlockCipher : StreamBlockCipher, SkippingStreamCipher
	{
		private readonly BlockCipher cipher;
		private readonly int blockSize;

		private byte[] IV;
		private byte[] counter;
		private byte[] counterOut;
		private int byteCount;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="c"> the block cipher to be used. </param>
		public SICBlockCipher(BlockCipher c) : base(c)
		{

			this.cipher = c;
			this.blockSize = cipher.getBlockSize();
			this.IV = new byte[blockSize];
			this.counter = new byte[blockSize];
			this.counterOut = new byte[blockSize];
			this.byteCount = 0;
		}

		public override void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;
				this.IV = Arrays.clone(ivParam.getIV());

				if (blockSize < IV.Length)
				{
					throw new IllegalArgumentException("CTR/SIC mode requires IV no greater than: " + blockSize + " bytes.");
				}

				int maxCounterSize = (8 > blockSize / 2) ? blockSize / 2 : 8;

				if (blockSize - IV.Length > maxCounterSize)
				{
					throw new IllegalArgumentException("CTR/SIC mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
				}

				// if null it's an IV changed only.
				if (ivParam.getParameters() != null)
				{
					cipher.init(true, ivParam.getParameters());
				}

				reset();
			}
			else
			{
				throw new IllegalArgumentException("CTR/SIC mode requires ParametersWithIV");
			}
		}

		public override string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/SIC";
		}

		public override int getBlockSize()
		{
			return cipher.getBlockSize();
		}

		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			processBytes(@in, inOff, blockSize, @out, outOff);

			return blockSize;
		}

		public override byte calculateByte(byte @in)
		{
			if (byteCount == 0)
			{
				cipher.processBlock(counter, 0, counterOut, 0);

				return (byte)(counterOut[byteCount++] ^ @in);
			}

			byte rv = (byte)(counterOut[byteCount++] ^ @in);

			if (byteCount == counter.Length)
			{
				byteCount = 0;

				incrementCounterAt(0);

				checkCounter();
			}

			return rv;
		}

		private void checkCounter()
		{
			// if the IV is the same as the blocksize we assume the user knows what they are doing
			if (IV.Length < blockSize)
			{
				for (int i = 0; i != IV.Length; i++)
				{
					if (counter[i] != IV[i])
					{
						throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
					}
				}
			}
		}

		private void incrementCounterAt(int pos)
		{
			int i = counter.Length - pos;
			while (--i >= 0)
			{
				if (++counter[i] != 0)
				{
					break;
				}
			}
		}

		private void incrementCounter(int offSet)
		{
			byte old = counter[counter.Length - 1];

			counter[counter.Length - 1] += (byte)offSet;

			if (old != 0 && counter[counter.Length - 1] < old)
			{
				incrementCounterAt(1);
			}
		}

		private void decrementCounterAt(int pos)
		{
			int i = counter.Length - pos;
			while (--i >= 0)
			{
				if (--counter[i] != -1)
				{
					return;
				}
			}
		}

		private void adjustCounter(long n)
		{
			if (n >= 0)
			{
				long numBlocks = (n + byteCount) / blockSize;

				long rem = numBlocks;
				if (rem > 255)
				{
					for (int i = 5; i >= 1; i--)
					{
						long diff = 1L << (8 * i);
						while (rem >= diff)
						{
							incrementCounterAt(i);
							rem -= diff;
						}
					}
				}

				incrementCounter((int)rem);

				byteCount = (int)((n + byteCount) - (blockSize * numBlocks));
			}
			else
			{
				long numBlocks = (-n - byteCount) / blockSize;

				long rem = numBlocks;
				if (rem > 255)
				{
					for (int i = 5; i >= 1; i--)
					{
						long diff = 1L << (8 * i);
						while (rem > diff)
						{
							decrementCounterAt(i);
							rem -= diff;
						}
					}
				}

				for (long i = 0; i != rem; i++)
				{
					decrementCounterAt(0);
				}

				int gap = (int)(byteCount + n + (blockSize * numBlocks));

				if (gap >= 0)
				{
					byteCount = 0;
				}
				else
				{
					decrementCounterAt(0);
					byteCount = blockSize + gap;
				}
			}
		}

		public override void reset()
		{
			Arrays.fill(counter, 0);
			JavaSystem.arraycopy(IV, 0, counter, 0, IV.Length);
			cipher.reset();
			this.byteCount = 0;
		}

		public virtual long skip(long numberOfBytes)
		{
			adjustCounter(numberOfBytes);

			checkCounter();

			cipher.processBlock(counter, 0, counterOut, 0);

			return numberOfBytes;
		}

		public virtual long seekTo(long position)
		{
			reset();

			return skip(position);
		}

		public virtual long getPosition()
		{
			byte[] res = new byte[counter.Length];

			JavaSystem.arraycopy(counter, 0, res, 0, res.Length);

			for (int i = res.Length - 1; i >= 1; i--)
			{
				int v;
				if (i < IV.Length)
				{
					v = (res[i] & 0xff) - (IV[i] & 0xff);
				}
				else
				{
					v = (res[i] & 0xff);
				}

				if (v < 0)
				{
				   res[i - 1]--;
				   v += 256;
				}

				res[i] = (byte)v;
			}

			return Pack.bigEndianToLong(res, res.Length - 8) * blockSize + byteCount;
		}
	}

}