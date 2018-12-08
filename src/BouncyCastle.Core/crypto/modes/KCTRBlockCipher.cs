using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Implementation of DSTU7624 CTR mode
	/// </summary>
	public class KCTRBlockCipher : StreamBlockCipher
	{
		private byte[] iv;
		private byte[] ofbV;
		private byte[] ofbOutV;

		private int byteCount;

		private bool initialised;
		private BlockCipher engine;

		public KCTRBlockCipher(BlockCipher engine) : base(engine)
		{

			this.engine = engine;
			this.iv = new byte[engine.getBlockSize()];
			this.ofbV = new byte[engine.getBlockSize()];
			this.ofbOutV = new byte[engine.getBlockSize()];
		}

		public override void init(bool forEncryption, CipherParameters @params)
		{
			this.initialised = true;

			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;
				byte[] iv = ivParam.getIV();
				int diff = this.iv.Length - iv.Length;

				Arrays.fill(this.iv, (byte)0);
				JavaSystem.arraycopy(iv, 0, this.iv, diff, iv.Length);
				@params = ivParam.getParameters();
			}
			else
			{
				throw new IllegalArgumentException("invalid parameter passed");
			}

			if (@params != null)
			{
				engine.init(true, @params);
			}

			reset();
		}

		public override string getAlgorithmName()
		{
			return engine.getAlgorithmName() + "/KCTR";
		}

		public override int getBlockSize()
		{
			return engine.getBlockSize();
		}

		public override byte calculateByte(byte b)
		{
			if (byteCount == 0)
			{
				incrementCounterAt(0);

				checkCounter();

				engine.processBlock(ofbV, 0, ofbOutV, 0);

				return (byte)(ofbOutV[byteCount++] ^ b);
			}

			byte rv = (byte)(ofbOutV[byteCount++] ^ b);

			if (byteCount == ofbV.Length)
			{
				byteCount = 0;
			}

			return rv;
		}

		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (@in.Length - inOff < getBlockSize())
			{
				throw new DataLengthException("input buffer too short");
			}
			if (@out.Length - outOff < getBlockSize())
			{
				throw new OutputLengthException("output buffer too short");
			}

			processBytes(@in, inOff, getBlockSize(), @out, outOff);

			return getBlockSize();
		}

		public override void reset()
		{
			if (initialised)
			{
				engine.processBlock(this.iv, 0, ofbV, 0);
			}
			engine.reset();
			byteCount = 0;
		}

		private void incrementCounterAt(int pos)
		{
			int i = pos;
			while (i < ofbV.Length)
			{
				if (++ofbV[i++] != 0)
				{
					break;
				}
			}
		}

		private void checkCounter()
		{
			// TODO:
			// if the IV is the same as the blocksize we assume the user knows what they are doing
	//        if (IV.length < ofbV.length)
	//        {
	//            for (int i = 0; i != IV.length; i++)
	//            {
	//                if (ofbV[i] != IV[i])
	//                {
	//                    throw new IllegalStateException("Counter in KCTR mode out of range.");
	//                }
	//            }
	//        }
		}
	}

}